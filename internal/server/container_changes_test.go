package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestGithubRepoFromSourceLabel(t *testing.T) {
	good := map[string]string{
		"https://github.com/immich-app/immich":        "immich-app/immich",
		"https://github.com/traefik/traefik.git":      "traefik/traefik",
		"https://github.com/linuxserver/docker-plex/": "linuxserver/docker-plex",
		"git@github.com:owner/repo.git":               "owner/repo",
		"github.com/a/b.c":                            "a/b.c",
	}
	for in, want := range good {
		if got, ok := githubRepo(in); !ok || got != want {
			t.Errorf("%s: got %q %v", in, got, ok)
		}
	}
	// None of these may become a request, to GitHub or anywhere else.
	for _, bad := range []string{"", "https://gitlab.com/a/b", "https://github.com.evil.example/a/b", "https://evil.example/github.com/a/b",
		"https://github.com/a", "https://github.com/a/b/c", "https://github.com/a/..", "https://github.com/a/b?x=1", "https://github.com/a/b#c", "https://github.com/-a/b"} {
		if got, ok := githubRepo(bad); ok {
			t.Errorf("%q gave %q", bad, got)
		}
	}
}

func TestReleasesURLOnlyForGithubSources(t *testing.T) {
	if u := releasesURL(proto.ContainerInfo{Source: "https://github.com/a/b"}); u != "https://github.com/a/b/releases" {
		t.Errorf("got %q", u)
	}
	if u := releasesURL(proto.ContainerInfo{Source: "javascript:alert(1)"}); u != "" {
		t.Errorf("got %q", u)
	}
}

func TestChangesForPicksReleasesBetweenVersions(t *testing.T) {
	releases := []githubRelease{
		{Tag: "v1.122.0", Body: "newest"}, {Tag: "v1.121.0", Prerelease: true}, {Tag: "v1.120.1", Body: "fix"},
		{Tag: "v1.120.0"}, {Tag: "v1.119.0", Body: "running"}, {Tag: "v1.118.0"}, {Tag: "not-a-version"},
	}
	tags := func(n []containerReleaseNote) string {
		var out []string
		for _, r := range n {
			out = append(out, r.Tag)
		}
		return strings.Join(out, ",")
	}
	// Pinned: from the running tag to the newer one.
	got, running, note := changesFor(proto.ContainerInfo{Image: "ghcr.io/immich-app/immich-server:v1.119.0", NewerTag: "v1.120.1"}, releases)
	if tags(got) != "v1.120.1,v1.120.0" || running != "v1.119.0" || note != "" {
		t.Errorf("pinned: %s %s %q", tags(got), running, note)
	}
	// latest: the version label says what is running, and everything newer counts.
	got, running, _ = changesFor(proto.ContainerInfo{Image: "app:latest", ImageVersion: "1.120.0"}, releases)
	if tags(got) != "v1.122.0,v1.120.1" || running != "1.120.0" {
		t.Errorf("latest: %s %s", tags(got), running)
	}
	// Nothing says what runs: the newest few, and a note saying so.
	got, running, note = changesFor(proto.ContainerInfo{Image: "app:latest"}, releases)
	if len(got) != 5 || running != "" || !strings.Contains(note, "not known") {
		t.Errorf("unknown: %s %q", tags(got), note)
	}
	// Up to date with releases: say so rather than return nothing silently.
	_, _, note = changesFor(proto.ContainerInfo{Image: "app:v1.122.0"}, releases)
	if !strings.Contains(note, "No releases newer") {
		t.Errorf("current: %q", note)
	}
}

func TestReleaseNotesAreBoundedAndCached(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/repos/owner/repo/releases" {
			t.Errorf("asked for %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode([]githubRelease{{Tag: "v2.0.0", Body: strings.Repeat("x", maxReleaseBody+100)}})
	}))
	defer srv.Close()
	old := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = old }()

	for range 2 {
		releases, err := fetchReleases(context.Background(), "owner/repo")
		if err != nil || len(releases) != 1 {
			t.Fatal(releases, err)
		}
		notes, _, _ := changesFor(proto.ContainerInfo{Image: "app:1.0.0"}, releases)
		if len(notes) != 1 || len(notes[0].Notes) != maxReleaseBody || !notes[0].Truncated {
			t.Fatalf("not bounded: %d %v", len(notes[0].Notes), notes[0].Truncated)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("GitHub asked %d times", calls.Load())
	}
}
