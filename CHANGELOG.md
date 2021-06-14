# bedrock-web-vc-issuer ChangeLog

## 3.0.0 - TBD

### Changed
- **BREAKING**: Remove `axios` and use `@digitalbazaar/http-client`. This is
  breaking because errors thrown by the two libraries are not identical.
- Update deps.
  - **BREAKING**: Remove `jsonld-signatures` and get Ed25519Signature2018 suite
    from it's own library. `verificationMethod` param removed from suite
    constructor.
  - Rename `webkms-client` to `@digitalbazaar/webkms-client` and
    update to latest v6.0 that supports multiple asymmetric key types .
  - Use `vc-revocation-list@3.0`. `vc-revocation-list@1` have no impact here.
  - Rename `vc-js` to `@digitalbazaar/vc`.
  - Use `edv-client@9.0`.
- Update test deps to latest.

## 2.2.0 - 2020-10-07

### Changed
- Update deps.

## 2.1.0 - 2020-07-01

### Changed
- Update deps.
- Update test deps.
- Update CI workflow.

## 2.0.1 - 2020-06-29

### Changed
- Update test deps.

## 2.0.0 - 2020-06-24

### Changed
- **BREAKING**: Use edv-client@4. This is a breaking change here because of
  changes in how edv-client serializes documents.

## 1.1.0 - 2020-05-18

### Added
- Add `revokeCredential` API.
- Add support for CI and coverage workflow.

### Changed
- Update `Issuer` role with `read` access to the Credentials EDV.

## 1.0.0 - 2020-04-09

- See git history for changes previous to this release.
