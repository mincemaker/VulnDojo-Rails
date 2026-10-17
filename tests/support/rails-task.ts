import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);
type TaskResult = { id: number | null; cookie: string };

export async function createTask(
  port: number,
  task: { title: string; description?: string; color?: string },
): Promise<TaskResult> {
  return runTaskHelper(port, task);
}

export async function createImageTask(port: number, description: string): Promise<TaskResult> {
  return runTaskHelper(port, { description }, 'image');
}

async function runTaskHelper(port: number, task: object, kind = 'task'): Promise<TaskResult> {
  const { stdout } = await exec('bundle', ['exec', 'ruby', '-Itest', 'tests/support/rails.rb', String(port), JSON.stringify(task), kind], {
    env: { ...process.env, RAILS_ENV: 'test', VULN_CHALLENGES: '' },
  });
  const line = stdout.split('\n').find(value => value.startsWith('E2E_DATA='));
  if (!line) throw new Error('Rails helper returned no task data');
  return JSON.parse(line.slice('E2E_DATA='.length));
}
