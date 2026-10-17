import type { E2EConfig } from 'e2e';
import { web } from '@e2e-dev/web';
import { chatgpt } from 'e2e/oauth/chatgpt';

export default {
  tests: 'tests/**/*.e2e.ts',
  workers: 1,
  // Model setup is optional: current tests make no agent calls and need no login.
  agents: {
    default: {
      model: chatgpt('gpt-6-luna'),
      system: 'You are a thorough QA agent. Verify every outcome.',
    },
  },
  targets: [{
    engine: web(),
    app: {
      url: 'http://127.0.0.1:3101',
      readyUrl: 'http://127.0.0.1:3106/up',
      command: {
        executable: 'bundle',
        args: ['exec', 'ruby', 'tests/support/rails.rb', 'serve'],
        env: {
          RAILS_ENV: 'test',
          VULN_CHALLENGES: '',
          BUNDLE_PATH: '/usr/local/bundle',
          GEM_HOME: '/usr/local/bundle',
        },
        log: '.e2e/logs/rails.log',
      },
    },
  }],
} satisfies E2EConfig;
