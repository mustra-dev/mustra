package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Self Service categories: the sections the endpoint window files its
// catalog under. The list and each package's place in it are the
// operator's; the window only draws what the state reply says.

// selfServiceCategoryIcons are the icons a category may carry: a subset of
// the console's line-icon set (ICON_PATHS in static/app.js), copied into
// the Self Service window (CAT_ICONS in internal/selfservice/window.html),
// which an endpoint serves without the console's scripts. A test keeps the
// three lists in step.
var selfServiceCategoryIcons = []string{
	"globe", "book", "chat", "terminal", "sliders", "shield", "mail", "chart",
	"database", "download", "folder", "key", "lock", "star", "box", "rocket",
	"users", "cpu", "layers", "tag", "bag", "clock", "search", "sync", "plug",
}

// selfServiceCategoryNameMax is long enough for "Engineering and design
// tools" and short enough to stay on one line of the window's sidebar.
const selfServiceCategoryNameMax = 40

// selfServiceCategoriesResponse is the category list, in display order.
type selfServiceCategoriesResponse struct {
	Categories []store.SelfServiceCategory `json:"categories"`
	// Icons are the icon names a category may use.
	Icons []string `json:"icons"`
}

// selfServiceCategoryRequest creates or changes a category.
type selfServiceCategoryRequest struct {
	// Name is what the Self Service window shows: at most 40 characters,
	// unique ignoring case, and not "All" or "Other", which the window
	// uses itself.
	Name string `json:"name" api:"required"`
	// Icon is one of the response's Icons, or empty for none.
	Icon string `json:"icon"`
}

// selfServiceCategoryOrderRequest sets the display order.
type selfServiceCategoryOrderRequest struct {
	// IDs are every category, first to last.
	IDs []string `json:"ids" api:"required"`
}

func validSelfServiceCategory(body selfServiceCategoryRequest) (selfServiceCategoryRequest, error) {
	body.Name = strings.TrimSpace(body.Name)
	body.Icon = strings.TrimSpace(body.Icon)
	switch {
	case body.Name == "":
		return body, errors.New("name is required")
	case utf8.RuneCountInString(body.Name) > selfServiceCategoryNameMax:
		return body, fmt.Errorf("name is longer than %d characters", selfServiceCategoryNameMax)
	case strings.EqualFold(body.Name, "All"), strings.EqualFold(body.Name, "Other"):
		return body, fmt.Errorf("%q is a name the Self Service window uses itself", body.Name)
	case strings.ContainsAny(body.Name, "\r\n\t"):
		return body, errors.New("name must be one line")
	}
	if body.Icon != "" && !knownCategoryIcon(body.Icon) {
		return body, fmt.Errorf("unknown icon %q", body.Icon)
	}
	return body, nil
}

func knownCategoryIcon(name string) bool {
	for _, i := range selfServiceCategoryIcons {
		if i == name {
			return true
		}
	}
	return false
}

func (s *Server) writeSelfServiceCategories(w http.ResponseWriter, ctx context.Context) {
	cats, err := s.store.ListSelfServiceCategories(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, selfServiceCategoriesResponse{Categories: cats, Icons: selfServiceCategoryIcons})
}

func (s *Server) handleListSelfServiceCategories(w http.ResponseWriter, r *http.Request) {
	s.writeSelfServiceCategories(w, r.Context())
}

func (s *Server) handleCreateSelfServiceCategory(w http.ResponseWriter, r *http.Request) {
	var body selfServiceCategoryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body, err := validSelfServiceCategory(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	c, err := s.store.CreateSelfServiceCategory(r.Context(), store.SelfServiceCategory{
		ID: idgen.New("sscat-"), Name: body.Name, Icon: body.Icon, CreatedBy: who,
	})
	if errors.Is(err, store.ErrCategoryNameTaken) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil || c == nil {
		http.Error(w, errString(err), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "selfservice.category.create", Actor: who, Target: c.ID, Severity: "notice",
		Detail: map[string]any{"name": c.Name}})
	writeJSONStatus(w, http.StatusCreated, c)
}

func (s *Server) handleUpdateSelfServiceCategory(w http.ResponseWriter, r *http.Request) {
	var body selfServiceCategoryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	body, err := validSelfServiceCategory(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	c, err := s.store.UpdateSelfServiceCategory(r.Context(), store.SelfServiceCategory{
		ID: r.PathValue("id"), Name: body.Name, Icon: body.Icon, UpdatedBy: who,
	})
	if errors.Is(err, store.ErrCategoryNameTaken) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if c == nil {
		http.NotFound(w, r)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "selfservice.category.update", Actor: who, Target: c.ID, Severity: "notice",
		Detail: map[string]any{"name": c.Name, "icon": c.Icon}})
	writeJSONResponse(w, c)
}

func (s *Server) handleDeleteSelfServiceCategory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ok, err := s.store.DeleteSelfServiceCategory(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "selfservice.category.delete", Actor: auth.CurrentUser(r.Context()).Username,
		Target: id, Severity: "notice"})
	w.WriteHeader(http.StatusNoContent)
}

// handleReorderSelfServiceCategories takes the whole list, so two
// operators reordering at once cannot interleave into an order neither
// chose: the later one wins outright, or is refused when the list changed
// under it.
func (s *Server) handleReorderSelfServiceCategories(w http.ResponseWriter, r *http.Request) {
	var body selfServiceCategoryOrderRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 {
		http.Error(w, "ids is required", http.StatusBadRequest)
		return
	}
	cats, err := s.store.ListSelfServiceCategories(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	known := map[string]bool{}
	for _, c := range cats {
		known[c.ID] = true
	}
	seen := map[string]bool{}
	for _, id := range body.IDs {
		if !known[id] || seen[id] {
			http.Error(w, "the order must list every category once; reload and try again", http.StatusConflict)
			return
		}
		seen[id] = true
	}
	if len(seen) != len(known) {
		http.Error(w, "the order must list every category once; reload and try again", http.StatusConflict)
		return
	}
	who := auth.CurrentUser(r.Context()).Username
	if err := s.store.ReorderSelfServiceCategories(r.Context(), body.IDs, who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), auditEvent{Action: "selfservice.category.reorder", Actor: who, Target: "selfservice", Severity: "info"})
	s.writeSelfServiceCategories(w, r.Context())
}

// cleanCategoryIDs checks a package's categories before it is saved: each
// must exist, and each is kept once. Nil stays nil, which keeps the
// package's current categories.
func (s *Server) cleanCategoryIDs(ctx context.Context, ids []string) ([]string, error) {
	if ids == nil {
		return nil, nil
	}
	cats, err := s.store.ListSelfServiceCategories(ctx)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, c := range cats {
		known[c.ID] = true
	}
	out := []string{}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		if !known[id] {
			return nil, errCategoryGone
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, nil
}

var errCategoryGone = errors.New("a Self Service category no longer exists; reload and try again")
