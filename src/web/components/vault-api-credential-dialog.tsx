import { useState, type FormEvent } from 'react';
import { api, errorMessage } from '../lib/api';
import { PasswordInput } from './password-input';
import {
  Button,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
  Field,
  Input,
  Notice,
} from './ui';

export function VaultApiCredentialDialog({ onClose }: { onClose(): void }) {
  const [auth, setAuth] = useState('bearer');
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (saving) return;
    const form = event.currentTarget;
    setSaving(true);
    setError('');
    try {
      await api('/api/vault/api-credentials', {
        method: 'POST',
        body: JSON.stringify(Object.fromEntries(new FormData(form))),
      });
      form.reset();
      setSaved(true);
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !saving && onClose()}>
      <DialogContent className="app-discovery-dialog" aria-busy={saving}>
        <DialogTitle>Add API credential</DialogTitle>
        <DialogDescription>
          {saved
            ? 'The credential is saved and the connection passed its read check.'
            : 'Nod checks the credential against the API. Manage the connection in Apps.'}
        </DialogDescription>
        {saved ? (
          <a className="button button-primary" href="/apps">
            View in Apps
          </a>
        ) : (
          <form onSubmit={(event) => void submit(event)} autoComplete="off">
            <Field label="Name">
              <Input disabled={saving} name="name" required maxLength={80} />
            </Field>
            <Field label="HTTPS API address">
              <Input disabled={saving} name="endpoint" type="url" required maxLength={2048} />
            </Field>
            <Field label="Read check path">
              <Input
                disabled={saving}
                name="testPath"
                placeholder="/account"
                required
                maxLength={2048}
              />
            </Field>
            <Field label="Authentication">
              <select
                className="input"
                name="auth"
                disabled={saving}
                value={auth}
                onChange={(event) => setAuth(event.target.value)}
              >
                <option value="bearer">Bearer token</option>
                <option value="x-api-key">API key header</option>
              </select>
            </Field>
            {auth === 'x-api-key' && (
              <Field label="Header name">
                <Input
                  disabled={saving}
                  name="apiKeyHeader"
                  placeholder="X-API-Key"
                  maxLength={100}
                />
              </Field>
            )}
            <Field label="API key or token">
              <PasswordInput
                name="token"
                revealLabel="API credential"
                autoComplete="off"
                required
                maxLength={8192}
                disabled={saving}
              />
            </Field>
            {error && <Notice>{error}</Notice>}
            <Button type="submit" disabled={saving}>
              {saving ? 'Checking access…' : 'Save credential'}
            </Button>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
