package com.threatgate.service;

import com.threatgate.db.UserJdbcDao;
import com.threatgate.exception.AuthenticationException;
import com.threatgate.exception.DatabaseException;
import com.threatgate.exception.InvalidDataException;
import com.threatgate.exception.UnauthorizedRoleException;
import com.threatgate.model.GenericStore;
import com.threatgate.model.User;
import java.sql.Timestamp;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class AuthService {
    public static final String DEFAULT_ADMIN_EMAIL = "admin@threatgate.dev";
    public static final String DEFAULT_ADMIN_PASSWORD = "Admin123!";
    public static final String DEFAULT_VIEWER_EMAIL = "viewer@threatgate.dev";
    public static final String DEFAULT_VIEWER_PASSWORD = "Viewer123!";

    private final GenericStore<User, Integer> offlineUsers = new GenericStore<>();
    private final UserJdbcDao userJdbcDao;
    private volatile boolean useDatabase;
    private int nextOfflineId = 1;

    public AuthService(UserJdbcDao userJdbcDao, boolean useDatabase) {
        this.userJdbcDao = userJdbcDao;
        this.useDatabase = useDatabase;
        initDefaultOfflineUsers();
    }

    public synchronized void setUseDatabase(boolean useDatabase) {
        this.useDatabase = useDatabase;
    }

    public boolean isUseDatabase() {
        return useDatabase;
    }

    public synchronized void seedDefaultOfflineUsers() {
        initDefaultOfflineUsers();
    }

    private void initDefaultOfflineUsers() {
        if (offlineUsers.count() > 0) {
            return;
        }
        Timestamp now = new Timestamp(System.currentTimeMillis());
        User admin = new User(
                nextOfflineId++,
                1,
                DEFAULT_ADMIN_EMAIL,
                PasswordUtil.hashPassword(DEFAULT_ADMIN_PASSWORD),
                "admin",
                now
        );
        User viewer = new User(
                nextOfflineId++,
                1,
                DEFAULT_VIEWER_EMAIL,
                PasswordUtil.hashPassword(DEFAULT_VIEWER_PASSWORD),
                "viewer",
                now
        );
        offlineUsers.save(admin);
        offlineUsers.save(viewer);
    }

    public synchronized void replaceOfflineUsers(List<User> loadedUsers) {
        offlineUsers.clear();
        nextOfflineId = 1;
        if (loadedUsers != null) {
            for (User user : loadedUsers) {
                offlineUsers.save(user);
                if (user.getId() >= nextOfflineId) {
                    nextOfflineId = user.getId() + 1;
                }
            }
        }
        if (offlineUsers.count() == 0) {
            seedDefaultOfflineUsers();
        }
    }

    public List<User> getAllOfflineUsers() {
        return offlineUsers.findAll();
    }

    public User login(String email, String password) throws AuthenticationException, DatabaseException {
        if (email == null || email.trim().isEmpty() || password == null || password.isEmpty()) {
            throw new AuthenticationException("Email and password are required.");
        }
        String normalizedEmail = email.trim().toLowerCase();
        Optional<User> userOpt;
        if (useDatabase && userJdbcDao != null) {
            userOpt = userJdbcDao.findByEmail(normalizedEmail);
        } else {
            userOpt = findOfflineByEmail(normalizedEmail);
        }
        if (userOpt.isEmpty() || !PasswordUtil.verifyPassword(password, userOpt.get().getPasswordHash())) {
            throw new AuthenticationException("Invalid email or password.");
        }
        return userOpt.get();
    }

    public synchronized User register(String email, String password, int orgId)
            throws InvalidDataException, DatabaseException {
        if (email == null || !email.trim().matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")) {
            throw new InvalidDataException("Please provide a valid email address.");
        }
        if (password == null || password.length() < 8) {
            throw new InvalidDataException("Password must be at least 8 characters.");
        }
        if (orgId <= 0) {
            throw new InvalidDataException("Organization ID must be positive.");
        }
        String normalizedEmail = email.trim().toLowerCase();
        String hash = PasswordUtil.hashPassword(password);
        Timestamp now = new Timestamp(System.currentTimeMillis());

        if (useDatabase && userJdbcDao != null) {
            User newUser = new User(0, orgId, normalizedEmail, hash, "viewer", now);
            return userJdbcDao.create(newUser);
        }
        if (findOfflineByEmail(normalizedEmail).isPresent()) {
            throw new InvalidDataException("An account with that email already exists.");
        }
        User created = new User(nextOfflineId++, orgId, normalizedEmail, hash, "viewer", now);
        return offlineUsers.save(created);
    }

    public void requireRole(User actor, String requiredRole) throws UnauthorizedRoleException {
        if (actor == null) {
            throw new UnauthorizedRoleException(requiredRole, "none");
        }
        if (!requiredRole.equalsIgnoreCase(actor.getRole())) {
            throw new UnauthorizedRoleException(requiredRole, actor.getRole());
        }
    }

    public List<User> listUsers(User actor) throws UnauthorizedRoleException, DatabaseException {
        requireRole(actor, "admin");
        if (useDatabase && userJdbcDao != null) {
            return userJdbcDao.findAllByOrg(actor.getOrgId());
        }
        return offlineUsers.findMatching(user -> user.getOrgId() == actor.getOrgId()).stream()
                .collect(Collectors.toList());
    }

    private Optional<User> findOfflineByEmail(String normalizedEmail) {
        return offlineUsers.findAll().stream()
                .filter(user -> user.getEmail().equalsIgnoreCase(normalizedEmail))
                .findFirst();
    }
}
