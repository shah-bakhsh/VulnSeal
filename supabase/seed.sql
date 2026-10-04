-- VulnSeal Supabase Seed Data
INSERT INTO public.workspaces (id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Workspace', 'default-workspace')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.targets (id, workspace_id, url, name, is_demo, status, security_score)
VALUES (
  '00000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000001',
  'http://localhost:3000/demo-target',
  'VulnSeal Intentionally Vulnerable Demo Target',
  TRUE,
  'authorized',
  100
) ON CONFLICT (id) DO NOTHING;
