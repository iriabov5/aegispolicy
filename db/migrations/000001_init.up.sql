-- Documents представляет минимальный demo resource domain, а не DMS-модель.
CREATE TABLE documents (
    id text PRIMARY KEY,
    project_id text NOT NULL
);

-- Роль хранится как trusted fact уровня проекта; общий relationship graph отложен.
CREATE TABLE subject_project_roles (
    subject_id text NOT NULL,
    project_id text NOT NULL,
    role text NOT NULL CHECK (role IN ('VIEWER', 'EDITOR')),
    PRIMARY KEY (subject_id, project_id)
);

-- Audit содержит достаточные данные для корреляции без credentials и raw context.
CREATE TABLE authorization_decisions (
    decision_id uuid PRIMARY KEY,
    decision text NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
    reasons jsonb NOT NULL,
    policy_name text,
    policy_revision text,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    decided_at timestamptz NOT NULL
);

-- Индекс поддерживает будущий просмотр истории решений конкретного субъекта.
CREATE INDEX authorization_decisions_subject_time_idx
    ON authorization_decisions (subject_id, decided_at DESC);

-- Детерминированные local-development facts для примеров и E2E.
INSERT INTO documents (id, project_id) VALUES
    ('doc-1', 'project-1'),
    ('doc-2', 'project-1');

INSERT INTO subject_project_roles (subject_id, project_id, role) VALUES
    ('ivan', 'project-1', 'EDITOR'),
    ('anna', 'project-1', 'VIEWER');
