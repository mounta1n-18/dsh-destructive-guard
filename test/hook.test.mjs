import assert from 'node:assert/strict'
import os from 'node:os'
import test from 'node:test'

import { apply } from '../index.js'

const HOME = os.homedir()

/**
 * 最小 Cordis ctx：只实现 apply 用到的 on / guard / effect / inject / get。
 * `policy` 模拟会话日志里的最后一次切换（undefined = 没有切换过，走配置默认值）。
 */
function makeContext({ policy, configured = 'ask' } = {}) {
  const pre = []
  const guards = []
  const tools = {
    effect(fn) {
      fn()
      return () => {}
    },
    on(event, handler) {
      if (event === 'tools/pre-execute') pre.push(handler)
      return () => {}
    },
    guard(handler) {
      guards.push(handler)
      return () => {}
    },
  }
  tools.tools = tools
  const ctx = {
    logger: { info() {}, warn() {} },
    get(name) {
      if (name === 'approval') {
        return { config: { policy: configured }, overrideOf: () => policy }
      }
      if (name === 'sessions') return { get: (id) => ({ id }) }
      return undefined
    },
    effect(fn) {
      fn()
      return () => {}
    },
    inject(deps, callback) {
      if (deps.includes('tools')) callback(tools)
      // webServer 不在这个测试范围内；不回调即可
    },
  }
  return { ctx, pre, guards }
}

const exec = (command) => ({ name: 'pwsh', arguments: { command }, agent: { id: 'session-1' } })
const writeExec = (file_path) => ({ name: 'write', arguments: { file_path }, agent: { id: 'session-1' } })
const next = async () => ({ kind: 'allow' })

test('wires pre-execute and monotonic guard without executing anything', async () => {
  const { ctx, pre, guards } = makeContext()
  apply(ctx)
  assert.equal(pre.length, 1, 'pre-execute handler registered')
  assert.equal(guards.length, 1, 'monotonic guard registered')

  const denied = await pre[0](exec(`Remove-Item -Recurse -Force $HOME`), next)
  assert.equal(denied.kind, 'deny')
  assert.match(denied.reason, /FS-HOME/)

  const allowed = await pre[0](exec('echo ok'), next)
  assert.equal(allowed.kind, 'allow')

  const asked = await pre[0](exec('git reset --hard'), next)
  assert.equal(asked.kind, 'ask')

  assert.match(guards[0](exec(`Remove-Item -Recurse -Force ${HOME}`)), /FS-HOME/)
  assert.equal(guards[0](exec('echo ok')), undefined)
  assert.equal(guards[0](exec('git reset --hard')), undefined)
})

test('never policy downgrades ask to deny with the rule name and a fix hint', async () => {
  const never = makeContext({ policy: 'never' })
  apply(never.ctx)
  const denied = await never.pre[0](exec('git reset --hard'), next)
  assert.equal(denied.kind, 'deny')
  assert.match(denied.reason, /GIT-DESTRUCTIVE/)
  assert.match(denied.reason, /never/)
  assert.match(denied.reason, /ask 档/)
  assert.match(denied.reason, /git reset --hard/)

  // block 级规则在 never 下照旧拒绝，理由不变。
  const blocked = await never.pre[0](exec(`Remove-Item -Recurse -Force ${HOME}`), next)
  assert.equal(blocked.kind, 'deny')
  assert.match(blocked.reason, /FS-HOME/)
  assert.doesNotMatch(blocked.reason, /approval policy = never/)

  // 兜底守卫（tools.guard）仍只拦 block 级，ask 级不在这里处理。
  assert.equal(never.guards[0](exec('git reset --hard')), undefined)
})

test('ask policy keeps asking, and configured default never is honoured without an override', async () => {
  const ask = makeContext({ policy: 'ask' })
  apply(ask.ctx)
  assert.equal((await ask.pre[0](exec('git reset --hard'), next)).kind, 'ask')

  // 没有会话级切换时，读 approval 插件的配置默认值。
  const configuredNever = makeContext({ policy: undefined, configured: 'never' })
  apply(configuredNever.ctx)
  const denied = await configuredNever.pre[0](exec('git push --force origin main'), next)
  assert.equal(denied.kind, 'deny')
  assert.match(denied.reason, /GIT-DESTRUCTIVE/)
  assert.match(denied.reason, /never/)

  // 读不到 approval 服务时按 ask 处理，不影响拦截。
  const noApproval = makeContext()
  noApproval.ctx.get = () => undefined
  apply(noApproval.ctx)
  assert.equal((await noApproval.pre[0](exec('git reset --hard'), next)).kind, 'ask')
})

test('write / edit into protected files is denied before execution', async () => {
  const { ctx, pre, guards } = makeContext()
  apply(ctx)
  const denied = await pre[0](writeExec(`${HOME}\\.dsh\\sessions\\s-1.jsonl`), next)
  assert.equal(denied.kind, 'deny')
  assert.match(denied.reason, /FS-PROTECTED/)

  const blockedByGuard = guards[0](writeExec(`${HOME}\\.dsh\\.credentials.yaml`))
  assert.match(blockedByGuard, /FS-PROTECTED/)

  const allowed = await pre[0](writeExec('C:\\DSH Plugin\\dsh-destructive-guard\\README.md'), next)
  assert.equal(allowed.kind, 'allow')
})

test('reading secret files is denied, ordinary files pass', async () => {
  const { ctx, pre, guards } = makeContext()
  apply(ctx)
  const ssh = await pre[0]({ name: 'read', arguments: { file_path: `${HOME}\\.ssh\\id_ed25519` } }, next)
  assert.equal(ssh.kind, 'deny')
  assert.match(ssh.reason, /SECRET-READ/)

  const env = await pre[0]({ name: 'read', arguments: { file_path: 'D:\\work\\proj\\.env' } }, next)
  assert.equal(env.kind, 'deny')

  const creds = guards[0]({ name: 'read', arguments: { file_path: `${HOME}\\.dsh\\.credentials.yaml` } })
  assert.match(creds, /SECRET-READ/)

  const ok = await pre[0]({ name: 'read', arguments: { file_path: 'D:\\work\\proj\\.env.example' } }, next)
  assert.equal(ok.kind, 'allow')
})

test('fails open on an unknown tool and on an empty command', async () => {
  const { ctx, pre } = makeContext()
  apply(ctx)
  assert.equal((await pre[0]({ name: 'grep', arguments: { pattern: 'x' } }, next)).kind, 'allow')
  assert.equal((await pre[0](exec(''), next)).kind, 'allow')
})
