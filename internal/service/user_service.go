package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/aefw/hapm/internal/domain"
	"github.com/aefw/hapm/internal/security"
)

// userService implements domain.UserService
type userService struct {
	repo     domain.UserRepository
	auditSvc domain.AuditService
}

// NewUserService membuat instance UserService baru
func NewUserService(repo domain.UserRepository, auditSvc domain.AuditService) domain.UserService {
	return &userService{repo: repo, auditSvc: auditSvc}
}

// GetByID mengambil user berdasarkan ID
func (s *userService) GetByID(ctx context.Context, id int) (*domain.User, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("user: find by id: %w", err)
	}
	return user, nil
}

// List mengembalikan semua user dengan filter dan pagination
func (s *userService) List(ctx context.Context, filter domain.ListFilter) ([]*domain.User, int, error) {
	users, total, err := s.repo.List(ctx, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("user: list: %w", err)
	}
	return users, total, nil
}

// Create membuat user baru dengan validasi dan hash password
func (s *userService) Create(ctx context.Context, req *domain.CreateUserRequest, actorID int) (*domain.User, error) {
	// Validasi input
	if req.Username == "" {
		return nil, errors.New("username is required")
	}
	if req.Email == "" {
		return nil, errors.New("email is required")
	}
	if len(req.Password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}
	if !isValidRole(req.Role) {
		return nil, errors.New("invalid role")
	}

	// Cek duplikat username
	if _, err := s.repo.FindByUsername(ctx, req.Username); err == nil {
		return nil, errors.New("username already exists")
	}

	// Cek duplikat email
	if _, err := s.repo.FindByEmail(ctx, req.Email); err == nil {
		return nil, errors.New("email already exists")
	}

	// Hash password dengan Argon2id
	hash, err := security.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("user: hash password: %w", err)
	}

	user := &domain.User{
		Username: req.Username,
		Email:    req.Email,
		Password: hash,
		FullName: req.FullName,
		Role:     req.Role,
		Active:   true,
	}

	id, err := s.repo.Create(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("user: create: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionUserCreated,
		ResourceType: "user",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Created user %s with role %s", req.Username, req.Role),
	})

	created, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("user: fetch after create: %w", err)
	}
	created.Password = "" // jangan expose hash
	return created, nil
}

// Update memperbarui data user
func (s *userService) Update(ctx context.Context, id int, req *domain.UpdateUserRequest, actorID int) (*domain.User, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("user: find by id: %w", err)
	}

	// Validasi role jika diubah
	if req.Role != "" && !isValidRole(req.Role) {
		return nil, errors.New("invalid role")
	}

	// Cek duplikat email jika diubah
	if req.Email != "" && req.Email != user.Email {
		if _, err := s.repo.FindByEmail(ctx, req.Email); err == nil {
			return nil, errors.New("email already exists")
		}
		user.Email = req.Email
	}

	if req.FullName != "" {
		user.FullName = req.FullName
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	if req.Active != nil {
		user.Active = *req.Active
	}

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("user: update: %w", err)
	}

	// Audit trail
	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionUserUpdated,
		ResourceType: "user",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Updated user %s", user.Username),
	})

	return user, nil
}

// Delete menghapus user berdasarkan ID
func (s *userService) Delete(ctx context.Context, id int, actorID int) error {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("user: find by id: %w", err)
	}

	// Tidak boleh hapus diri sendiri
	if id == actorID {
		return errors.New("cannot delete your own account")
	}

	// Tidak boleh hapus superadmin kecuali oleh superadmin lain
	if user.Role == domain.RoleSuperAdmin {
		actor, err := s.repo.FindByID(ctx, actorID)
		if err != nil || actor.Role != domain.RoleSuperAdmin {
			return errors.New("only superadmin can delete superadmin accounts")
		}
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("user: delete: %w", err)
	}

	// Audit trail
	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       domain.AuditActionUserDeleted,
		ResourceType: "user",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Deleted user %s", user.Username),
	})

	return nil
}

// SetLocked mengunci atau membuka kunci akun user
func (s *userService) SetLocked(ctx context.Context, id int, locked bool, actorID int) error {
	if err := s.repo.SetLocked(ctx, id, locked, nil); err != nil {
		return fmt.Errorf("user: set locked: %w", err)
	}

	action := domain.AuditActionUserLocked
	detail := "Account locked"
	if !locked {
		detail = "Account unlocked"
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       action,
		ResourceType: "user",
		ResourceID:   &id,
		Detail:       detail,
	})

	return nil
}

// isValidRole memvalidasi nilai role
func isValidRole(role string) bool {
	switch role {
	case domain.RoleSuperAdmin, domain.RoleAdmin, domain.RoleOperator, domain.RoleViewer:
		return true
	}
	return false
}
