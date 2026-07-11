package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/bcrypt"

	"github.com/aefw/hapm/internal/domain"
)

// authUsernameRe memvalidasi username untuk HAProxy userlist.
var authUsernameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// ─── AuthUserService ──────────────────────────────────────────────────────────

type haproxyAuthUserService struct {
	repo     domain.AuthUserRepository
	auditSvc domain.AuditService
}

func NewAuthUserService(repo domain.AuthUserRepository, auditSvc domain.AuditService) domain.AuthUserService {
	return &haproxyAuthUserService{repo: repo, auditSvc: auditSvc}
}

func (s *haproxyAuthUserService) GetByID(ctx context.Context, id int) (*domain.AuthUser, error) {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("auth_user: find by id: %w", err)
	}
	return u, nil
}

func (s *haproxyAuthUserService) List(ctx context.Context, filter domain.ListFilter) ([]*domain.AuthUser, int, error) {
	return s.repo.List(ctx, filter)
}

func (s *haproxyAuthUserService) Create(ctx context.Context, req *domain.CreateAuthUserRequest, actorID int) (*domain.AuthUser, error) {
	if req.Username == "" {
		return nil, errors.New("username wajib diisi")
	}
	if !authUsernameRe.MatchString(req.Username) {
		return nil, errors.New("username tidak valid: hanya huruf, angka, titik, hyphen, underscore (max 64 karakter)")
	}
	if req.Password == "" {
		return nil, errors.New("password wajib diisi saat membuat user")
	}

	if _, err := s.repo.FindByUsername(ctx, req.Username); err == nil {
		return nil, errors.New("username sudah ada")
	}

	hash, err := hashAuthPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("auth_user: hash password: %w", err)
	}

	u := &domain.AuthUser{
		Username:     req.Username,
		PasswordHash: hash,
		Description:  req.Description,
		Enabled:      req.Enabled,
	}
	id, err := s.repo.Create(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("auth_user: create: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       "auth_user.create",
		ResourceType: "auth_user",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Created auth user %s", req.Username),
	})

	return s.repo.FindByID(ctx, id)
}

func (s *haproxyAuthUserService) Update(ctx context.Context, id int, req *domain.CreateAuthUserRequest, actorID int) (*domain.AuthUser, error) {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("auth_user: find by id: %w", err)
	}

	if req.Username != "" && req.Username != u.Username {
		if !authUsernameRe.MatchString(req.Username) {
			return nil, errors.New("username tidak valid")
		}
		if _, err := s.repo.FindByUsername(ctx, req.Username); err == nil {
			return nil, errors.New("username sudah ada")
		}
		u.Username = req.Username
	}

	if req.Password != "" {
		hash, err := hashAuthPassword(req.Password)
		if err != nil {
			return nil, fmt.Errorf("auth_user: hash password: %w", err)
		}
		u.PasswordHash = hash
	}

	u.Description = req.Description
	u.Enabled = req.Enabled

	if err := s.repo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("auth_user: update: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       "auth_user.update",
		ResourceType: "auth_user",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Updated auth user %s", u.Username),
	})

	return u, nil
}

func (s *haproxyAuthUserService) Delete(ctx context.Context, id int, actorID int) error {
	u, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("auth_user: find by id: %w", err)
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("auth_user: delete: %w", err)
	}
	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       "auth_user.delete",
		ResourceType: "auth_user",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Deleted auth user %s", u.Username),
	})
	return nil
}

// ─── AuthGroupService ─────────────────────────────────────────────────────────

type haproxyAuthGroupService struct {
	repo     domain.AuthGroupRepository
	userRepo domain.AuthUserRepository
	auditSvc domain.AuditService
}

func NewAuthGroupService(repo domain.AuthGroupRepository, userRepo domain.AuthUserRepository, auditSvc domain.AuditService) domain.AuthGroupService {
	return &haproxyAuthGroupService{repo: repo, userRepo: userRepo, auditSvc: auditSvc}
}

func (s *haproxyAuthGroupService) GetByID(ctx context.Context, id int) (*domain.AuthGroup, error) {
	g, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("auth_group: find by id: %w", err)
	}
	return g, nil
}

func (s *haproxyAuthGroupService) List(ctx context.Context, filter domain.ListFilter) ([]*domain.AuthGroup, int, error) {
	return s.repo.List(ctx, filter)
}

func (s *haproxyAuthGroupService) Create(ctx context.Context, req *domain.CreateAuthGroupRequest, actorID int) (*domain.AuthGroup, error) {
	if req.GroupName == "" {
		return nil, errors.New("group_name wajib diisi")
	}
	if _, err := s.repo.FindByName(ctx, req.GroupName); err == nil {
		return nil, errors.New("nama group sudah ada")
	}

	g := &domain.AuthGroup{
		GroupName:   req.GroupName,
		Description: req.Description,
		Enabled:     req.Enabled,
	}
	id, err := s.repo.Create(ctx, g)
	if err != nil {
		return nil, fmt.Errorf("auth_group: create: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       "auth_group.create",
		ResourceType: "auth_group",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Created auth group %s", req.GroupName),
	})

	return s.repo.FindByID(ctx, id)
}

func (s *haproxyAuthGroupService) Update(ctx context.Context, id int, req *domain.CreateAuthGroupRequest, actorID int) (*domain.AuthGroup, error) {
	g, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("auth_group: find by id: %w", err)
	}

	if req.GroupName != "" && req.GroupName != g.GroupName {
		if _, err := s.repo.FindByName(ctx, req.GroupName); err == nil {
			return nil, errors.New("nama group sudah ada")
		}
		g.GroupName = req.GroupName
	}
	g.Description = req.Description
	g.Enabled = req.Enabled

	if err := s.repo.Update(ctx, g); err != nil {
		return nil, fmt.Errorf("auth_group: update: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       "auth_group.update",
		ResourceType: "auth_group",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Updated auth group %s", g.GroupName),
	})

	return g, nil
}

func (s *haproxyAuthGroupService) Delete(ctx context.Context, id int, actorID int) error {
	g, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return fmt.Errorf("auth_group: find by id: %w", err)
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("auth_group: delete: %w", err)
	}
	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       "auth_group.delete",
		ResourceType: "auth_group",
		ResourceID:   &id,
		Detail:       fmt.Sprintf("Deleted auth group %s", g.GroupName),
	})
	return nil
}

func (s *haproxyAuthGroupService) ListMembers(ctx context.Context, groupID int) ([]*domain.AuthUser, error) {
	if _, err := s.repo.FindByID(ctx, groupID); err != nil {
		return nil, fmt.Errorf("auth_group: find by id: %w", err)
	}
	return s.repo.ListMembers(ctx, groupID)
}

func (s *haproxyAuthGroupService) AddMember(ctx context.Context, groupID int, req *domain.AddGroupMemberRequest, actorID int) error {
	g, err := s.repo.FindByID(ctx, groupID)
	if err != nil {
		return fmt.Errorf("auth_group: find by id: %w", err)
	}
	u, err := s.userRepo.FindByID(ctx, req.AuthUserID)
	if err != nil {
		return fmt.Errorf("auth_user: find by id: %w", err)
	}

	already, _ := s.repo.IsMember(ctx, groupID, req.AuthUserID)
	if already {
		return errors.New("user sudah menjadi member group ini")
	}

	if err := s.repo.AddMember(ctx, groupID, req.AuthUserID); err != nil {
		return fmt.Errorf("auth_group: add member: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       "auth_group.member.add",
		ResourceType: "auth_group",
		ResourceID:   &groupID,
		Detail:       fmt.Sprintf("Added user %s to group %s", u.Username, g.GroupName),
	})
	return nil
}

func (s *haproxyAuthGroupService) RemoveMember(ctx context.Context, groupID, userID int, actorID int) error {
	g, err := s.repo.FindByID(ctx, groupID)
	if err != nil {
		return fmt.Errorf("auth_group: find by id: %w", err)
	}
	u, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("auth_user: find by id: %w", err)
	}

	if err := s.repo.RemoveMember(ctx, groupID, userID); err != nil {
		return fmt.Errorf("auth_group: remove member: %w", err)
	}

	_ = s.auditSvc.Log(ctx, &domain.AuditLog{
		UserID:       &actorID,
		Action:       "auth_group.member.remove",
		ResourceType: "auth_group",
		ResourceID:   &groupID,
		Detail:       fmt.Sprintf("Removed user %s from group %s", u.Username, g.GroupName),
	})
	return nil
}

// hashAuthPassword menghasilkan bcrypt hash ($2b format) kompatibel dengan HAProxy 3.x.
func hashAuthPassword(password string) (string, error) {
	if len(password) < 6 {
		return "", errors.New("password minimal 6 karakter")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
