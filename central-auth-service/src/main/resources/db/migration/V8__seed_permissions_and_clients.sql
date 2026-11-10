-- =============================================================================
-- V8: Seed global permission catalog and default auth clients
-- =============================================================================
-- Initial permission catalog entries from Section 11.
INSERT INTO permissions (id, resource, action, description, registered_by) VALUES
    (gen_random_uuid(), 'USER',              'CREATE',   'Create a user',                   'central-auth-service'),
    (gen_random_uuid(), 'USER',              'READ',     'Read user details',               'central-auth-service'),
    (gen_random_uuid(), 'USER',              'UPDATE',   'Update a user',                   'central-auth-service'),
    (gen_random_uuid(), 'USER',              'DELETE',   'Delete/deactivate a user',        'central-auth-service'),
    (gen_random_uuid(), 'ROLE',              'CREATE',   'Create a role',                   'central-auth-service'),
    (gen_random_uuid(), 'ROLE',              'ASSIGN',   'Assign roles to users',           'central-auth-service'),
    (gen_random_uuid(), 'COMPANY_SETTINGS',  'UPDATE',   'Update company settings',         'central-auth-service'),
    (gen_random_uuid(), 'DOCUMENT',          'READ',     'Read documents',                  'document-service'),
    (gen_random_uuid(), 'DOCUMENT',          'UPLOAD',   'Upload documents',                'document-service'),
    (gen_random_uuid(), 'PURCHASE',          'CREATE',   'Create purchase orders',          'purchase-service'),
    (gen_random_uuid(), 'PURCHASE',          'APPROVE',  'Approve purchase orders',         'purchase-service'),
    (gen_random_uuid(), 'VENDOR',            'MANAGE',   'Manage vendors',                  'vendor-service');

-- Default registered auth clients (Section 30.1).
INSERT INTO auth_clients (id, client_id, display_name, client_type, is_confidential, enabled) VALUES
    (gen_random_uuid(), 'central-auth-web',     'Central Auth Web Client',     'WEB',            false, true),
    (gen_random_uuid(), 'central-auth-desktop', 'Central Auth Desktop Client', 'DESKTOP',        false, true),
    (gen_random_uuid(), 'central-auth-mobile',  'Central Auth Mobile Client',  'MOBILE_ANDROID', false, true);
