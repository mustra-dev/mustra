package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

// What changed in a container's update, read from the GitHub releases of the
// repository its image names in the org.opencontainers.image.source label.
//
// Only GitHub, because that is where most images' projects publish release
// notes, and only for images that set the label. The label comes from the
// image's publisher through the endpoint, so it is matched against a strict
// pattern and only ever turned into a GitHub URL: it cannot point the server
// anywhere else.

var githubSourcePattern = regexp.MustCompile(`^(?:https?://|git@)?github\.com[/:]([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?/?$`)

// githubRepo is the owner/name an image's source label names on GitHub.
func githubRepo(source string) (string, bool) {
	m := githubSourcePattern.FindStringSubmatch(strings.TrimSpace(source))
	if m == nil || m[2] == "." || m[2] == ".." {
		return "", false
	}
	return m[1] + "/" + m[2], true
}

// releasesURL is where a person reads what changed, when the image says.
func releasesURL(c proto.ContainerInfo) string {
	if repo, ok := githubRepo(c.Source); ok {
		return "https://github.com/" + repo + "/releases"
	}
	return ""
}

const (
	releaseNotesCacheFor = time.Hour
	maxReleasesListed    = 20
	maxReleaseBody       = 4000
)

type githubRelease struct {
	Tag         string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	URL         string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
}

var releaseCache = struct {
	sync.Mutex
	byRepo map[string]cachedReleases
}{byRepo: map[string]cachedReleases{}}

type cachedReleases struct {
	releases []githubRelease
	at       time.Time
}

// fetchReleases reads a repository's most recent releases, cached because
// GitHub allows an unauthenticated caller 60 requests an hour.
func fetchReleases(ctx context.Context, repo string) ([]githubRelease, error) {
	releaseCache.Lock()
	cached, ok := releaseCache.byRepo[repo]
	releaseCache.Unlock()
	if ok && time.Since(cached.at) < releaseNotesCacheFor {
		return cached.releases, nil
	}
	owner, name, _ := strings.Cut(repo, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		githubAPI+"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/releases?per_page=100", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "mustra")
	resp, err := followClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered %s", resp.Status)
	}
	var releases []githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&releases); err != nil {
		return nil, fmt.Errorf("GitHub's answer was not readable: %w", err)
	}
	releaseCache.Lock()
	if len(releaseCache.byRepo) > 500 {
		clear(releaseCache.byRepo)
	}
	releaseCache.byRepo[repo] = cachedReleases{releases: releases, at: time.Now()}
	releaseCache.Unlock()
	return releases, nil
}

var releaseVersionPattern = regexp.MustCompile(`^[vV]?([0-9]+(?:\.[0-9]+)*)`)

// releaseVersion reads the numbers a tag starts with: v1.2.3-alpine is 1.2.3.
func releaseVersion(tag string) ([]int64, bool) {
	m := releaseVersionPattern.FindStringSubmatch(strings.TrimSpace(tag))
	if m == nil {
		return nil, false
	}
	var nums []int64
	for p := range strings.SplitSeq(m[1], ".") {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return nil, false
		}
		nums = append(nums, n)
	}
	return nums, true
}

// compareVersions orders versions of different lengths as 1.2 = 1.2.0.
func compareVersions(a, b []int64) int {
	for i := range max(len(a), len(b)) {
		var x, y int64
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// containerReleaseNote is one release in what list_container_changes answers.
type containerReleaseNote struct {
	Tag         string `json:"tag"`
	Name        string `json:"name,omitempty"`
	PublishedAt string `json:"published_at,omitempty"`
	URL         string `json:"url"`
	Notes       string `json:"notes"`
	Truncated   bool   `json:"notes_truncated,omitempty"`
}

// containerChanges is what list_container_changes answers.
type containerChanges struct {
	Container   string                 `json:"container"`
	Hostname    string                 `json:"hostname"`
	Image       string                 `json:"image"`
	Source      string                 `json:"source,omitempty"`
	ReleasesURL string                 `json:"releases_url,omitempty"`
	Running     string                 `json:"running_version,omitempty"`
	Target      string                 `json:"target_version,omitempty"`
	Releases    []containerReleaseNote `json:"releases"`
	Note        string                 `json:"note,omitempty"`
}

// runningVersion is what the container runs: its tag when the tag is a
// version, otherwise the version label the image carries.
func runningVersion(c proto.ContainerInfo) string {
	if _, tag, ok := strings.Cut(lastPathPart(c.Image), ":"); ok {
		if _, isVersion := releaseVersion(tag); isVersion {
			return tag
		}
	}
	if _, ok := releaseVersion(c.ImageVersion); ok {
		return c.ImageVersion
	}
	return ""
}

func lastPathPart(image string) string {
	image, _, _ = strings.Cut(image, "@")
	if i := strings.LastIndex(image, "/"); i >= 0 {
		return image[i+1:]
	}
	return image
}

// changesFor picks the releases after the running version, up to the newer
// tag when there is one. Pre-releases and drafts are left out.
func changesFor(c proto.ContainerInfo, releases []githubRelease) ([]containerReleaseNote, string, string) {
	running, target := runningVersion(c), c.NewerTag
	from, haveFrom := releaseVersion(running)
	to, haveTo := releaseVersion(target)
	var out []containerReleaseNote
	for _, r := range releases {
		if r.Draft || r.Prerelease {
			continue
		}
		v, ok := releaseVersion(r.Tag)
		if !ok || (haveFrom && compareVersions(v, from) <= 0) || (haveTo && compareVersions(v, to) > 0) {
			continue
		}
		note := containerReleaseNote{Tag: r.Tag, Name: r.Name, PublishedAt: r.PublishedAt, URL: r.URL, Notes: r.Body}
		if len(note.Notes) > maxReleaseBody {
			note.Notes, note.Truncated = strings.ToValidUTF8(note.Notes[:maxReleaseBody], ""), true
		}
		out = append(out, note)
		if len(out) == maxReleasesListed {
			break
		}
	}
	note := ""
	switch {
	case !haveFrom:
		note = "The running version is not known (no version tag or label), so these are the newest releases rather than the ones since it."
	case len(out) == 0:
		note = "No releases newer than the running version were found on GitHub; the image may be rebuilt without a new release."
	}
	if !haveFrom && len(out) > 5 {
		out = out[:5]
	}
	return out, running, note
}
