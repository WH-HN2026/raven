package httpapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/WH-HN2026/raven/internal/auth"
	"github.com/WH-HN2026/raven/internal/httpx"
	"github.com/WH-HN2026/raven/internal/users"
)

// User administration (task P2). Logic and rules live in internal/users.
func (a *api) mountUsers(r chi.Router) {
	r.With(auth.Require(auth.PermUsersAdmin)).Get("/users", a.listUsers)
	r.With(auth.Require(auth.PermUsersAdmin)).Post("/users", a.createUser)
	r.With(auth.Require(auth.PermUsersAdmin)).Patch("/users/{id}", a.updateUser)
	r.With(auth.Require(auth.PermUsersAdmin)).Delete("/users/{id}", a.deleteUser)
}

func (a *api) userStore() *users.Store { return &users.Store{Pool: a.Pool} }

func usersError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, users.ErrNotFound):
		httpx.Error(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, users.ErrConflict):
		httpx.Error(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, users.ErrInvalid):
		httpx.Error(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, users.ErrForbidden):
		httpx.Error(w, http.StatusConflict, "not_allowed", err.Error())
	case errors.Is(err, users.ErrWrongPassword):
		httpx.Error(w, http.StatusBadRequest, "wrong_password", err.Error())
	default:
		slog.Error(op, "err", err)
		httpx.Error(w, http.StatusInternalServerError, "internal", op+" failed")
	}
}

func (a *api) listUsers(w http.ResponseWriter, r *http.Request) {
	order, ok := listOrder(w, r, "username", "role", "status", "created_at")
	if !ok {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	items, total, err := a.userStore().List(r.Context(), limit, offset, order)
	if err != nil {
		usersError(w, "list users", err)
		return
	}
	httpx.JSON(w, http.StatusOK, list[users.User]{Items: items, Total: total})
}

func (a *api) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string    `json:"username"`
		Password string    `json:"password"`
		Role     auth.Role `json:"role"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	u, err := a.userStore().Create(r.Context(), auth.UserFrom(r.Context()), in.Username, in.Password, in.Role)
	if err != nil {
		usersError(w, "create user", err)
		return
	}
	httpx.JSON(w, http.StatusCreated, u)
}

func (a *api) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var p users.Patch
	if !httpx.DecodeJSON(w, r, &p) {
		return
	}
	u, err := a.userStore().Update(r.Context(), auth.UserFrom(r.Context()), id, p)
	if err != nil {
		usersError(w, "update user", err)
		return
	}
	httpx.JSON(w, http.StatusOK, u)
}

func (a *api) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := a.userStore().Delete(r.Context(), auth.UserFrom(r.Context()), id); err != nil {
		usersError(w, "delete user", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// changeOwnPassword: PATCH /api/auth/me/password, any logged-in user.
func (a *api) changeOwnPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !httpx.DecodeJSON(w, r, &in) {
		return
	}
	var token string
	if c, err := r.Cookie(auth.CookieName); err == nil {
		token = c.Value
	}
	if err := a.userStore().ChangeOwnPassword(r.Context(), auth.UserFrom(r.Context()), token, in.CurrentPassword, in.NewPassword); err != nil {
		usersError(w, "change password", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
