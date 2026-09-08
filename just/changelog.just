# Preview unreleased Conventional Commits for a version.
[group('changelog')]
changelog_preview version:
  git-cliff --config cliff.toml --unreleased --tag "v{{ version }}" --strip all

# Generate CHANGELOG.md through the requested version.
[group('changelog')]
changelog version:
  git-cliff --config cliff.toml --tag "v{{ version }}" --output CHANGELOG.md
  just fmt CHANGELOG.md

# Tag a version and create a GitHub release with the changelog section as notes. Does not publish to crates.io.
[group('changelog')]
gh_release version:
  notes="$(just changelog_preview {{ version }})" && \
  git tag "v{{ version }}" && \
  git push origin "v{{ version }}" && \
  echo "$notes" | gh release create "v{{ version }}" --title "v{{ version }}" --notes-file -
