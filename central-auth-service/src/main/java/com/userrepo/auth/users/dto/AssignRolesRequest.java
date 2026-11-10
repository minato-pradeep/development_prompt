package com.userrepo.auth.users.dto;

import jakarta.validation.constraints.NotEmpty;

import java.util.List;
import java.util.UUID;

public record AssignRolesRequest(@NotEmpty List<UUID> roleIds) {}
