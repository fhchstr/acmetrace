// Package acmetrace implements functions for requesting certificates using the ACME protocol
// (see https://acmeprotocol.dev). The particularity of this package, compared to other ACME
// client packages, is that this one records and exposes the responses returned by the CA
// (Certificate Authority) during the certificate issuance process, as well as other information
// related to the issuance flow. This may be useful for applications that need to analyze the
// details of the ACME transaction.
//
// By ignoring the additional details provided, this package can also simply be used as a regular
// ACME client package to request certificates using the ACME protocol.
package acmetrace

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/acme"
	"golang.org/x/sync/errgroup"
)

// ACMETracer is an ACME client that records details of the ACME transaction
// during the certificate issuance process.
type ACMETracer struct {
	// client is the underlying ACME client of the ACME tracer.
	client *acme.Client
	// logger is a function that gets called to log events.
	logger func(format string, a ...any)

	// dns01ChallengePublisher is used to prove domain control by publishing
	// solved ACME dns-01 challenges in DNS records.
	dns01ChallengePublisher challenge.Provider
	// http01ChallengePublisher is used to prove domain control by publishing
	// solved ACME http-01 challenges in resources served via HTTP.
	http01ChallengePublisher challenge.Provider

	// accountKeyPath is the file path of the ACME account private key.
	// If it is set, and the file exists, ACMETracer assumes that the key
	// corresponds to an *already registered* ACME account. If it is set,
	// and the file doesn't exist, ACMETracer generates a new key, uses it
	// to register a new ACME account, and writes the key to accountKeyPath.
	// If it isn't set, ACMETracer generates a new key, uses it to register
	// a new ACME account, but doesn't write the key to a file.
	accountKeyPath string
	// eab holds the data needed to register an ACME account with external
	// account binding. It is only used when registering a new ACME account.
	// See https://acmeprotocol.dev/acme/eab/.
	eab *acme.ExternalAccountBinding
	// account is the ACME account used by the ACMETracer. It is either a
	// newly registered account, or an existing account retrieved using the
	// key read from accountKeyPath.
	account *acme.Account
	// accountOnce ensures that the ACME account registration, or lookup
	// in the case of an existing ACME account, is only performed once in
	// the lifetime of the ACMETracer.
	accountOnce sync.Once
}

// NewACMETracer returns a new ACMETracer instantiated using the given options.
func NewACMETracer(opts ...ACMETracerOpt) (*ACMETracer, error) {
	ret := &ACMETracer{
		client: &acme.Client{UserAgent: "acmetrace/1.0"},
		logger: func(string, ...any) {}, // Use a no-op logger by default.
	}
	for _, opt := range opts {
		if err := opt(ret); err != nil {
			return nil, err
		}
	}

	if ret.client.DirectoryURL == "" {
		return nil, fmt.Errorf("ACME directory URL is not set")
	}
	if ret.dns01ChallengePublisher == nil && ret.http01ChallengePublisher == nil {
		return nil, fmt.Errorf("no ACME challenge publisher is specified")
	}
	return ret, nil
}

// ACMETracerOpt is an option for instantiating the ACMETracer.
type ACMETracerOpt func(*ACMETracer) error

// WithDirectoryURL instructs the ACMETracer to connect to the given ACME directory URL.
func WithDirectoryURL(s string) ACMETracerOpt {
	return func(t *ACMETracer) error { t.client.DirectoryURL = s; return nil }
}

// WithLogger instructs the ACMETracer to use the given function when logging events.
func WithLogger(f func(format string, a ...any)) ACMETracerOpt {
	return func(t *ACMETracer) error { t.logger = f; return nil }
}

// WithAccountKeyPath instructs the ACMETracer to either (depending whether a file exists
// at the given path) use an exising ACME account tied to the key at the given path, or
// store the newly generated account key at the given path after having registered a new
// ACME account.
func WithAccountKeyPath(path string) ACMETracerOpt {
	return func(t *ACMETracer) error { t.accountKeyPath = path; return nil }
}

// WithEAB instruct the ACMETracer to transmit external account binding information
// to the CA when registering a new ACME account. See https://acmeprotocol.dev/acme/eab/.
func WithEAB(kid string, mac []byte) ACMETracerOpt {
	return func(t *ACMETracer) error { t.eab = &acme.ExternalAccountBinding{KID: kid, Key: mac}; return nil }
}

// WithDNS01Publisher instructs the ACMETracer to use the publisher with the given name
// when solving dns-01 ACME challenges. See https://go-acme.github.io/lego/dns/ for
// supported values and the corresponding environment variables required for authentication.
func WithDNS01Publisher(name string) ACMETracerOpt {
	return func(t *ACMETracer) error {
		publisher, err := dns.NewDNSChallengeProviderByName(name)
		if err != nil {
			return fmt.Errorf("failed to initialize dns-01 challenge publisher: %v", err)
		}
		t.dns01ChallengePublisher = publisher
		return nil
	}
}

// WithHTTP01Publisher instructs the ACMETracer to use the publisher with the given name
// when solving http-01 ACME challenges. DO NOT USE. Support for http-01 is not implemented yet.
func WithHTTP01Publisher(name string) ACMETracerOpt {
	return func(t *ACMETracer) error { return fmt.Errorf("http-01 publisher is not implemented yet") }
}

// Trace holds the details of the ACME flow for a certificate request.
// If certificate issuance is successful, Trace includes the issued
// certificate and its correspoinding chain(s).
// See https://acmeprotocol.dev/acme/overview/ for additional information
// regarding the ACME flow.
type Trace struct {
	// tracer is the ACMETracer used to perform the trace.
	tracer *ACMETracer

	// Identifiers holds the domain names and/or IP addresses requested to be included in the certificate.
	Identifiers []string
	// CertKey is the private key of the requested certificate.
	CertKey crypto.Signer
	// AccountKey is the private key of the ACME account used to request the certificate.
	AccountKey crypto.Signer
	// CSR is the Certificate Signing Request for the certificate.
	CSR *x509.CertificateRequest

	mu               sync.Mutex
	Account          *acme.Account         // ACME account used to request the certificate.
	Order            *acme.Order           // Order used to request the certificate. See https://acmeprotocol.dev/acme/overview/#order-initiation.
	Authorizations   []*acme.Authorization // ACME authorizations for all identifiers requested to be included in the certificate.
	SolvedChallenges []ChallengeAnswer     // Solved ACME DCV (Domain Control Validation) challenges to complete the authorizations.
	CertURL          string                // URL for downloading the issued certificate.
	// Chains for the issued certificate. The first item is the newly issued leaf certificate.
	// The remaining items are CA certificates, up to (but excluding!) the trust anchor (a.k.a. self-signed root CA).
	// See https://acmeprotocol.dev/acme/overview/#:~:text=download%20the%20issued%20certificate for more information.
	CertificateChains [][]*x509.Certificate
}

// ChallengeAnswer holds the data required to complete an ACME challenge.
type ChallengeAnswer struct {
	Identifier       string          // Identifier tired to the challenge and authorization.
	KeyAuthorization string          // Solution of the challenge. See https://acmeprotocol.dev/acme/challenges/.
	Challenge        *acme.Challenge // Challenge object.
}

// RequestCertificate requests a certificate for the given key that includes the given identifiers (domain names and/or IP addresses)
// from the CA using the ACME protocol. This goes through the whole ACME flow, including DCV (Domain Control Validation)
// for the identifiers not already authorized for the ACME account used for the request.
// The returned Trace is never nil, even if a non-nil error is returned, in which case some of the Trace's fields may not be set.
func (t *ACMETracer) RequestCertificate(ctx context.Context, key crypto.Signer, identifiers []string) (*Trace, error) {
	trace := &Trace{
		tracer:      t,
		Identifiers: identifiers,
		CertKey:     key,
	}
	if len(identifiers) == 0 {
		return trace, fmt.Errorf("no identifiers provided")
	}
	if key == nil {
		return trace, fmt.Errorf("no certificate private key provided")
	}

	// TODO: This is a problem. The account should be copied. We don't want to return a reference to it.
	var err error
	t.accountOnce.Do(func() { err = t.ensureAccount(ctx) })
	if err != nil {
		return trace, fmt.Errorf("failed to ensure an ACME account exists: %v", err)
	}
	trace.Account = t.account
	trace.AccountKey = t.client.Key

	if err := trace.newOrder(ctx); err != nil {
		return trace, fmt.Errorf("failed to initiate ACME order: %v", err)
	}
	if trace.Order.Status == acme.StatusInvalid {
		return trace, fmt.Errorf("ACME order is %q", acme.StatusInvalid)
	}
	if err := trace.fetchAuthorizations(ctx); err != nil {
		return trace, fmt.Errorf("failed to fetch authorizations tied to the ACME order: %v", err)
	}
	if trace.Order.Status != acme.StatusReady {
		cleanup, err := trace.solvePendingAuthorizations(ctx)
		defer cleanup() // cleanup() must be called even if a non-nil error is returned.
		if err != nil {
			return trace, fmt.Errorf("failed to solve pending authorizations tied to the ACME order: %v", err)
		}
		if err := t.ensureChallengesAreSolvedGlobally(); err != nil {
			return trace, fmt.Errorf("failed to ensure that the solved ACME challenges have propagated globally: %v", err)
		}
		if err := trace.acceptChallenges(ctx); err != nil {
			return trace, fmt.Errorf("failed to accept selected ACME challenges: %v", err)
		}
		if err := trace.waitOrderReady(ctx); err != nil {
			return trace, fmt.Errorf("ACME order is not ready to be finalized: %v", err)
		}
	}
	if err := trace.finalizeOrder(ctx); err != nil {
		return trace, fmt.Errorf("failed to finalize ACME order: %v", err)
	}
	if err := trace.downloadAlternateChains(ctx); err != nil {
		return trace, fmt.Errorf("failed to download alternate certificate chains: %v", err)
	}
	return trace, nil
}

// ensureAccount ensures that a usable ACME account exists, either by retrieving
// an existing one or by registering a new one.
func (t *ACMETracer) ensureAccount(ctx context.Context) error {
	if t.accountKeyPath != "" {
		accountKey, err := readSignerKey(t.accountKeyPath)
		// os.ErrNotExist is not considered a failure. If no file exists at that path,
		// a new key will be generated and written to that path when registering the ACME account.
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to read ACME account key: %v", err)
		}
		// It is safe to assign accountKey to c.client.Key even if readSignerKey()
		// returns os.ErrNotExist because accountKey would be nil in that case.
		t.client.Key = accountKey
	}

	if t.client.Key == nil {
		t.logger("Registering new ACME account with %s", t.client.DirectoryURL)
		if err := t.registerAccount(ctx); err != nil {
			return fmt.Errorf("failed to register ACME account: %v", err)
		}
	} else {
		t.logger("Reusing existing ACME account from %s using key from %s", t.client.DirectoryURL, t.accountKeyPath)
		if err := t.retrieveExistingAccount(ctx); err != nil {
			return fmt.Errorf("failed to retrieve existing ACME account: %v", err)
		}
	}

	t.logger("ACME Account:\n%s", prettyJSON(t.account))
	return nil
}

// readSignerKey reads the file at the given path and returns the crypto.Signer key it contains.
func readSignerKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("malformed key read from %s: %v", path, err)
	}
	ret, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key read from %s does not implement the crypto.Signer interface", path)
	}
	return ret, nil
}

// registerAccount registers a new ACME account.
func (t *ACMETracer) registerAccount(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate new ACME account key: %v", err)
	}
	t.client.Key = key

	accountSettings := &acme.Account{
		// Some CAs may require the contact field to be set, using a domain ending with a public suffix,
		// so let's set it to a dummy value since we are not interested to receive emails from the CA anyway.
		Contact:                []string{"mailto:dummy@does.not.exist.com"},
		ExternalAccountBinding: t.eab,
	}
	account, err := t.client.Register(ctx, accountSettings, acme.AcceptTOS)
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %v", err)
	}
	t.account = account

	// Save the generated key if a path was provided.
	if t.accountKeyPath != "" {
		data, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to marshal newly generated ACME account key to PKCS#8: %v", err)
		}
		if err := os.WriteFile(t.accountKeyPath, data, 0600); err != nil {
			return fmt.Errorf("failed to write newly generated ACME account key: %v", err)
		}
		t.logger("Newly generated ACME account key written to %s", t.accountKeyPath)
	}
	return nil
}

// retrieveExistingAccount retrieves an existing account associated with the
// client's key. It returns an error if no valid account exists.
func (t *ACMETracer) retrieveExistingAccount(ctx context.Context) error {
	account, err := t.client.GetReg(ctx, "") // The second argument is a legacy artifact of the pre-RFC 8555 API and is ignored.
	if err != nil {
		return fmt.Errorf("failed to retrieve existing ACME account: %v", err)
	}
	if account.Status != acme.StatusValid {
		return fmt.Errorf("status of retrieved ACME account is %q and not %q", account.Status, acme.StatusValid)
	}
	t.account = account
	return nil
}

// newOrder initiates a new ACME order, using the order-based flow.
func (t *Trace) newOrder(ctx context.Context) error {
	t.tracer.logger("Initiating the order-based ACME flow for requesting a certificate for %s", t.Identifiers)
	order, err := t.tracer.client.AuthorizeOrder(ctx, acmeIdentifiers(t.Identifiers))
	if err != nil {
		return fmt.Errorf("failed to initiate order-based ACME flow: %v", err)
	}
	t.Order = order
	t.tracer.logger("ACME order created:\n%s", prettyJSON(t.Order))
	return nil
}

// acmeIdentifiers converts a list of domain names and/or IP addresses to
// a list of ACME identifier objects, with the corresponding type set.
func acmeIdentifiers(identifiers []string) []acme.AuthzID {
	var ret []acme.AuthzID
	for _, identifier := range identifiers {
		typ := "dns"
		if ip := net.ParseIP(identifier); ip != nil {
			typ = "ip"
		}
		ret = append(ret, acme.AuthzID{Type: typ, Value: identifier})
	}
	return ret
}

// fetchAuthorizations retrieves the authorizations tied to the ongoing ACME order.
func (t *Trace) fetchAuthorizations(ctx context.Context) error {
	t.tracer.logger("Fetching authorizations for order %s", t.Order.URI)
	eg, ctx := errgroup.WithContext(ctx)
	for _, authzURL := range t.Order.AuthzURLs {
		eg.Go(func() error {
			authz, err := t.tracer.client.GetAuthorization(ctx, authzURL)
			if err != nil {
				return fmt.Errorf("failed to fetch authorization from %s: %v", authzURL, err)
			}
			t.mu.Lock()
			t.Authorizations = append(t.Authorizations, authz)
			nb := len(t.Authorizations)
			t.mu.Unlock()
			t.tracer.logger("Authorization #%d:\n%s", nb, prettyJSON(authz))
			return nil
		})
	}
	return eg.Wait()
}

// solvePendingAuthorizations solves the DCV (Domain Control Validation) challenges
// of all pending authorizations. The function returns a cleanup function that must
// be called after the CA validated the challenges or when the issuance process gets aborted.
func (t *Trace) solvePendingAuthorizations(ctx context.Context) (func() error, error) {
	t.tracer.logger("Solving pending authorizations for order %s", t.Order.URI)
	eg, _ := errgroup.WithContext(ctx)
	cleanupFuncs := make([]func() error, len(t.Authorizations))
	for i, authz := range t.Authorizations {
		eg.Go(func() error {
			cleanupFunc, err := t.solvePendingAuthorization(authz)
			cleanupFuncs[i] = cleanupFunc
			return err
		})
	}
	// The eg.Wait() call can't be in the return statement since joinFuncs() must be called *after* eg.Wait() returns.
	err := eg.Wait()
	return joinFuncs(cleanupFuncs), err
}

// joinFuncs returns a function that wraps the given functions. When called,
// the returned function calls all the wrapped function concurrently and
// merges their errors using errors.Join(). The function blocks until all
// wrapped functions terminate their execution.
func joinFuncs(funcs []func() error) func() error {
	return func() error {
		var wg sync.WaitGroup
		wg.Add(len(funcs))
		errs := make([]error, len(funcs))
		for i, f := range funcs {
			go func() {
				defer wg.Done()
				if f != nil {
					errs[i] = f()
				}
			}()
		}
		wg.Wait()
		return errors.Join(errs...)
	}
}

// solvePendingAuthorization completes the given authorization by publishing a solved ACME challenge
// to a publicly accessible location. solvePendingAuthorization() selects the ACME challenge type based
// on its own heuristics. solvePendingAuthorization() returns a cleanup function that must be called to
// tear down the solved ACME challenge after the CA validated it, or if the issuance
// process gets aborted.
func (t *Trace) solvePendingAuthorization(authz *acme.Authorization) (func() error, error) {
	noopCleanup := func() error { return nil }
	if authz.Status == acme.StatusValid {
		return noopCleanup, nil
	}
	if authz.Status != acme.StatusPending {
		return noopCleanup, fmt.Errorf("the authorization can't be completed because its state is %q", authz.Status)
	}

	answer, err := t.computeChallengeAnswer(authz)
	if err != nil {
		return noopCleanup, fmt.Errorf("failed to compute the answered challenge value for completing the authorization: %v", err)
	}
	publisher, err := t.tracer.publisher(answer.Challenge.Type)
	if err != nil {
		return noopCleanup, fmt.Errorf("failed to lookup the %q ACME challenge publisher for %s: %v", answer.Challenge.Type, authz.Identifier.Value, err)
	}
	if err := publisher.Present(authz.Identifier.Value, answer.Challenge.Token, answer.KeyAuthorization); err != nil {
		return noopCleanup, fmt.Errorf("failed to publish solved %q challenge for %s: %v", answer.Challenge.Type, authz.Identifier.Value, err)
	}
	cleanup := func() error {
		return publisher.CleanUp(authz.Identifier.Value, answer.Challenge.Token, answer.KeyAuthorization)
	}

	t.mu.Lock()
	t.SolvedChallenges = append(t.SolvedChallenges, answer)
	t.mu.Unlock()
	t.tracer.logger("Challenge solved:\n%s", prettyJSON(answer))

	return cleanup, nil
}

// computeChallengeAnswer selects a challenge and computes its answer for completing the given ACME authorization.
func (t *Trace) computeChallengeAnswer(authz *acme.Authorization) (ChallengeAnswer, error) {
	challenge, err := t.tracer.pickChallenge(authz)
	if err != nil {
		return ChallengeAnswer{}, fmt.Errorf("failed to pick challenge type for %s: %v", authz.Identifier.Value, err)
	}
	keyAuth, err := t.tracer.keyAuth(challenge.Token)
	if err != nil {
		return ChallengeAnswer{}, fmt.Errorf("failed to compute the keyAuthorization to solve the ACME challenge for %s: %v", authz.Identifier.Value, err)
	}
	return ChallengeAnswer{
		Identifier:       authz.Identifier.Value,
		KeyAuthorization: keyAuth,
		Challenge:        challenge,
	}, nil
}

// pickChallenge returns the optimal challenge for the given authorization.
// DNS changes may be slow to globally propagate, so other challenge types are preferred if available.
func (t *ACMETracer) pickChallenge(authz *acme.Authorization) (*acme.Challenge, error) {
	// preferredChallengeTypes holds the usable challenge types, sorted by preference.
	var preferredChallengeTypes []string
	if t.http01ChallengePublisher != nil {
		preferredChallengeTypes = append(preferredChallengeTypes, "http-01")
	}
	if t.dns01ChallengePublisher != nil {
		preferredChallengeTypes = append(preferredChallengeTypes, "dns-01")
	}

	challengesByType := make(map[string]*acme.Challenge)
	for _, challenge := range authz.Challenges {
		challengesByType[challenge.Type] = challenge
	}

	for _, challengeType := range preferredChallengeTypes {
		if challenge, ok := challengesByType[challengeType]; ok {
			return challenge, nil
		}
	}
	return nil, fmt.Errorf("no usable challenge type among the ones proposed by the CA: %s", strings.Join(slices.Sorted(maps.Keys(challengesByType)), ", "))
}

// keyAuth computes the keyAuthorization value for solving an ACME challenge.
// See https://acmeprotocol.dev/acme/challenges/ to understand how it is built.
// TL;DR: keyAuthorization = token || '.' || base64url(sha256(accountKey))
// where accountKey is in JWK (JSON Web Key) format.
func (t *ACMETracer) keyAuth(token string) (string, error) {
	jwk := &jose.JSONWebKey{Key: t.client.Key.Public()}
	accountKeyHash, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to compute SHA-256 hash of jwk account key: %v", err)
	}
	b64accountKeyHash := base64.RawURLEncoding.EncodeToString(accountKeyHash)
	return token + "." + b64accountKeyHash, nil
}

// publisher returns the publisher instance for the given challengeType.
func (t *ACMETracer) publisher(challengeType string) (challenge.Provider, error) {
	if challengeType == "dns-01" && t.dns01ChallengePublisher != nil {
		return t.dns01ChallengePublisher, nil
	}
	if challengeType == "http-01" && t.http01ChallengePublisher != nil {
		return t.http01ChallengePublisher, nil
	}
	return nil, fmt.Errorf("unsupported challenge type: %s", challengeType)
}

// ensureChallengesAreSolvedGlobally verifies that the answer of the selected challenges is published.
// TODO: implement.
func (t *ACMETracer) ensureChallengesAreSolvedGlobally() error {
	sleepDuration := 10 * time.Second
	t.logger("Sleeping %s to let the solved challenge(s) to propagate globally", sleepDuration)
	time.Sleep(sleepDuration)
	return nil
}

// acceptChallenges informs the CA that the ACME challenges have been solved and are ready to be verified.
func (t *Trace) acceptChallenges(ctx context.Context) error {
	t.tracer.logger("Accepting ACME challenges for order %s", t.Order.URI)
	eg, ctx := errgroup.WithContext(ctx)
	for _, solved := range t.SolvedChallenges {
		eg.Go(func() error {
			if _, err := t.tracer.client.Accept(ctx, solved.Challenge); err != nil {
				return fmt.Errorf("failed to accept ACME challenge: %v", err)
			}
			return nil
		})
	}
	return eg.Wait()
}

// waitOrderReady blocks until the ACME order is in the "ready" state.
func (t *Trace) waitOrderReady(ctx context.Context) error {
	t.tracer.logger("Waiting for order %s to be ready", t.Order.URI)
	var err error
	t.Order, err = t.tracer.client.WaitOrder(ctx, t.Order.URI)
	if err != nil {
		return fmt.Errorf("failed to wait for the ACME order to become %q: %v", acme.StatusReady, err)
	}
	if t.Order.Status != acme.StatusReady {
		return fmt.Errorf("order is %q, and not %q", t.Order.Status, acme.StatusReady)
	}
	return nil
}

// finalizeOrder finalizes the ACME order and downloads the issued certificate and its primary chain.
func (t *Trace) finalizeOrder(ctx context.Context) error {
	t.tracer.logger("Finalizing order %s", t.Order.URI)
	csr, err := t.makeCSR()
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %v", err)
	}

	var chain [][]byte
	chain, t.CertURL, err = t.tracer.client.CreateOrderCert(ctx, t.Order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("failed to finalize order: %v", err)
	}
	if err := t.addCertificateChain(chain); err != nil {
		return fmt.Errorf("failed to add primary certificate chain to the trace: %v", err)
	}
	return nil
}

// makeCSR generates a CSR (Certificate Signing Request) and returns it in raw format.
// It also sets the Trace.CSR field.
func (t *Trace) makeCSR() ([]byte, error) {
	tmpl := &x509.CertificateRequest{DNSNames: t.Identifiers}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, t.CertKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %v", err)
	}
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CSR: %v", err)
	}
	t.CSR = parsedCSR
	return csr, nil
}

// downloadAlternateChains downloads the altnernate certificate chains, if any.
func (t *Trace) downloadAlternateChains(ctx context.Context) error {
	t.tracer.logger("Downloading alternate chains for order %s", t.Order.URI)
	altURLs, err := t.tracer.client.ListCertAlternates(ctx, t.CertURL)
	if err != nil {
		return fmt.Errorf("failed to list alternate chains for certificate %s: %v", t.CertURL, err)
	}

	eg, ctx := errgroup.WithContext(ctx)
	for _, altURL := range altURLs {
		eg.Go(func() error {
			chain, err := t.tracer.client.FetchCert(ctx, altURL, true)
			if err != nil {
				return fmt.Errorf("failed to download alternate chain from %s: %v", altURL, err)
			}
			if err := t.addCertificateChain(chain); err != nil {
				return fmt.Errorf("failed to add downloaded alternate certificate chain to the trace: %v", err)
			}
			return nil
		})
	}
	return eg.Wait()
}

// addCertificateChain adds the given (raw) certificate chain to the Trace. It is safe to call it concurrently.
func (t *Trace) addCertificateChain(rawChain [][]byte) error {
	chain, err := x509Chain(rawChain)
	if err != nil {
		return fmt.Errorf("failed to parse X.509 certificate chain: %v", err)
	}
	t.mu.Lock()
	t.CertificateChains = append(t.CertificateChains, chain)
	nb := len(t.CertificateChains)
	t.mu.Unlock()

	chainPEM, err := pemChain(chain)
	if err != nil {
		return fmt.Errorf("failed to encode chain to PEM: %v", err)
	}
	t.tracer.logger("Certificate chain #%d:\n%s", nb, chainPEM)
	return nil
}

// x509Chain parses the []byte elements of the given [][]byte slice as X.509 certificates and returns them in the same order.
func x509Chain(chain [][]byte) ([]*x509.Certificate, error) {
	var ret []*x509.Certificate
	for _, rawCert := range chain {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, fmt.Errorf("malformed certificate: %v", err)
		}
		ret = append(ret, cert)
	}
	return ret, nil
}

// pemChain PEM-encodes the given certificate chain.
func pemChain(chain []*x509.Certificate) (string, error) {
	var buf bytes.Buffer
	for _, cert := range chain {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return "", fmt.Errorf("failed  to encode certificate to PEM: %v", err)
		}
	}
	return buf.String(), nil
}

// prettyJSON returns a nicely formatted string JSON representation of v.
func prettyJSON(v any) string {
	ret, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("failed to marshal value to JSON (see raw value below): %v\n%+v", err, v)
	}
	return string(ret)
}
