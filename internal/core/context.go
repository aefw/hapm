package core

import "context"

// contextKey adalah tipe private untuk menghindari collision di context
type contextKey string

const (
	// ContextKeyUserID menyimpan id_users dari JWT claims
	ContextKeyUserID contextKey = "user_id"
	// ContextKeyUsername menyimpan username dari JWT claims
	ContextKeyUsername contextKey = "username"
	// ContextKeyRole menyimpan role dari JWT claims
	ContextKeyRole contextKey = "role"
	// ContextKeyRequestID menyimpan unique request ID untuk tracing
	ContextKeyRequestID contextKey = "request_id"
)

// SetUserContext menyimpan user info ke dalam context
func SetUserContext(ctx context.Context, userID int, username, role string) context.Context {
	ctx = context.WithValue(ctx, ContextKeyUserID, userID)
	ctx = context.WithValue(ctx, ContextKeyUsername, username)
	ctx = context.WithValue(ctx, ContextKeyRole, role)
	return ctx
}

// GetUserID mengambil user ID dari context. Mengembalikan 0 jika tidak ada.
func GetUserID(ctx context.Context) int {
	if v, ok := ctx.Value(ContextKeyUserID).(int); ok {
		return v
	}
	return 0
}

// GetUsername mengambil username dari context. Mengembalikan "" jika tidak ada.
func GetUsername(ctx context.Context) string {
	if v, ok := ctx.Value(ContextKeyUsername).(string); ok {
		return v
	}
	return ""
}

// GetRole mengambil role dari context. Mengembalikan "" jika tidak ada.
func GetRole(ctx context.Context) string {
	if v, ok := ctx.Value(ContextKeyRole).(string); ok {
		return v
	}
	return ""
}

// GetRequestID mengambil request ID dari context.
func GetRequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ContextKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// SetRequestID menyimpan request ID ke dalam context
func SetRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, id)
}
