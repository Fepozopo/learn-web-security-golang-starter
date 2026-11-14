package reviews

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/database"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

// TestReviewManagementOwnership checks access and persisted changes for each management handler.
func TestReviewManagementOwnership(t *testing.T) {
	for _, action := range []string{"edit", "update", "delete"} {
		for _, subject := range []struct {
			name     string
			userID   int64
			reviewID string
		}{
			{name: "owner", userID: 1, reviewID: "10"},
			{name: "other user", userID: 2, reviewID: "10"},
			{name: "missing review", userID: 1, reviewID: "999"},
			{name: "invalid review", userID: 1, reviewID: "invalid"},
		} {
			t.Run(action+"/"+subject.name, func(t *testing.T) {
				ctx := context.Background()
				db, err := database.Open(ctx, filepath.Join(t.TempDir(), "test.sqlite"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				if err := database.Migrate(ctx, db); err != nil {
					t.Fatal(err)
				}
				_, err = db.ExecContext(ctx, `INSERT INTO users (id, email, display_name, role, password_hash) VALUES
					(1, 'owner@example.com', 'Owner', 'customer', 'unused'),
					(2, 'other@example.com', 'Other', 'customer', 'unused');
					INSERT INTO products (id, name, description, image_path, price_cents, cost_cents) VALUES (1, 'Product', '', '', 100, 0);
					INSERT INTO reviews (id, user_id, product_id, rating, body) VALUES (10, 1, 1, 3, 'Original review')`)
				if err != nil {
					t.Fatal(err)
				}
				accountStore := accounts.NewStore(db)
				session, err := accountStore.CreateSession(ctx, subject.userID)
				if err != nil {
					t.Fatal(err)
				}
				renderer, err := templates.Load(filepath.Join("..", "..", "web", "templates"))
				if err != nil {
					t.Fatal(err)
				}
				handler := NewHandler(NewStore(db), accountStore, renderer, nil)
				form := url.Values{"csrfToken": {session.CSRFToken}, "rating": {"5"}, "body": {"Updated review"}}
				method := http.MethodPost
				if action == "edit" {
					method = http.MethodGet
				}
				req := httptest.NewRequest(method, "/account/reviews/"+subject.reviewID, strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if err := req.ParseForm(); err != nil {
					t.Fatal(err)
				}
				req.SetPathValue("id", subject.reviewID)
				req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: session.Token})
				response := httptest.NewRecorder()
				switch action {
				case "edit":
					handler.Edit(response, req)
				case "update":
					handler.Update(response, req)
				case "delete":
					handler.Delete(response, req)
				}
				owned := subject.name == "owner"
				wantStatus := http.StatusNotFound
				if owned {
					wantStatus = http.StatusFound
					if action == "edit" {
						wantStatus = http.StatusOK
					}
				}
				if response.Code != wantStatus {
					t.Fatalf("%s as %s: status = %d, body = %q; want %d", action, subject.name, response.Code, response.Body.String(), wantStatus)
				}
				if !owned && !strings.Contains(response.Body.String(), "Review Not Found") {
					t.Errorf("%s as %s: body = %q; want Review Not Found", action, subject.name, response.Body.String())
				}
				var rating int64
				var body string
				err = db.QueryRowContext(ctx, "SELECT rating, body FROM reviews WHERE id = 10").Scan(&rating, &body)
				if owned && action == "delete" {
					if !errors.Is(err, sql.ErrNoRows) {
						t.Errorf("delete as owner: query error = %v; want sql.ErrNoRows", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				wantRating, wantBody := int64(3), "Original review"
				if owned && action == "update" {
					wantRating, wantBody = 5, "Updated review"
				}
				if rating != wantRating || body != wantBody {
					t.Errorf("%s as %s: review = (%d, %q); want (%d, %q)", action, subject.name, rating, body, wantRating, wantBody)
				}
			})
		}
	}
}
