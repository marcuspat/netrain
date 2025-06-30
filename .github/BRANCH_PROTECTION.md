# Branch Protection Rules for NetRain

This document outlines the recommended branch protection rules for the NetRain repository. These settings should be configured in the GitHub repository settings under Settings → Branches.

## Main Branch Protection

### Rule Pattern: `main`

#### Protection Settings

**Require a pull request before merging**
- ✅ Require approvals: 1
- ✅ Dismiss stale pull request approvals when new commits are pushed
- ✅ Require review from CODEOWNERS
- ✅ Restrict who can dismiss pull request reviews

**Require status checks to pass before merging**
- ✅ Require branches to be up to date before merging
- Required status checks:
  - `check`
  - `test (ubuntu-latest, stable)`
  - `test (macos-latest, stable)` 
  - `test (windows-latest, stable)`
  - `coverage`
  - `security-audit`

**Require conversation resolution before merging**
- ✅ All conversations must be resolved

**Require signed commits**
- ✅ All commits must be signed with GPG

**Require linear history**
- ✅ Prevent merge commits from being pushed

**Include administrators**
- ⬜ Do not include administrators (allow bypass for emergency fixes)

**Restrict who can push to matching branches**
- ✅ Restrict pushes that create matching branches
- Allowed users/teams: `NetRain-maintainers`

**Rules applied to everyone including administrators**
- ✅ Allow force pushes: Disabled
- ✅ Allow deletions: Disabled

## Development Branch Protection

### Rule Pattern: `develop`

#### Protection Settings

**Require a pull request before merging**
- ✅ Require approvals: 1
- ✅ Dismiss stale pull request approvals when new commits are pushed

**Require status checks to pass before merging**
- ✅ Require branches to be up to date before merging
- Required status checks:
  - `check`
  - `test (ubuntu-latest, stable)`
  - `coverage`

**Require conversation resolution before merging**
- ✅ All conversations must be resolved

**Allow force pushes**
- ⬜ Disabled

**Allow deletions**
- ⬜ Disabled

## Feature Branch Guidelines

Feature branches (pattern: `feature/*`) do not require protection rules but should follow these conventions:

1. Always create from `develop`
2. Use descriptive names: `feature/user-authentication`
3. Delete after merging
4. Keep branches short-lived (< 2 weeks)

## Hotfix Branch Guidelines

Hotfix branches (pattern: `hotfix/*`) for emergency production fixes:

1. Create from `main`
2. Merge to both `main` and `develop`
3. Require expedited review (1 approval)
4. Must pass all CI checks

## Additional Security Recommendations

1. **Enable Dependabot security updates**
   - Settings → Security & analysis → Dependabot security updates

2. **Enable secret scanning**
   - Settings → Security & analysis → Secret scanning

3. **Enable push protection for secrets**
   - Settings → Security & analysis → Push protection

4. **Configure CODEOWNERS file**
   - Create `.github/CODEOWNERS` to require specific reviewers for critical files

5. **Enable vulnerability alerts**
   - Settings → Security & analysis → Dependabot alerts

## Enforcement

These rules should be reviewed quarterly and updated based on team needs. Any changes to protection rules should be documented in the repository's changelog.