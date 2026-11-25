/**
 * 破坏性命令判定（纯函数，无副作用）。
 *
 * 设计原则：
 * 1. 只做“字符串静态分析”，不执行、不展开变量、不访问网络；
 * 2. 先判不可逆的家目录/系统/磁盘/恢复/日志/注册表类操作，再判可回滚的范围操作；
 * 3. 规则按 `block` → `ask` → `allow` 排序，命中即返回；
 * 4. 误报优先于漏报：宁可拒绝一条合法命令，也不放行一条删除家目录的命令。
 *
 * 这不是沙箱。它只能拦住“命令字符串里看得见”的模式；编码、混淆、GUI 自动化、
 * 自写程序仍然可以绕过，必须配合权限沙箱与备份使用。
 */

import os from 'node:os'

const HOME = normalize(os.homedir()).replace(/\/+$/, '')

/** 家目录之外的“整体根”保护：删掉这些根等于大面积数据损失。 */
const EXTRA_PROTECTED = ['c:/dshprojects', 'c:/dsh plugin', 'c:/ccprojects', 'd:/归档']

/** 家目录下需要整体保护的一级目录。 */
const PROTECTED_CHILDREN = [
  'desktop',
  'documents',
  'downloads',
  'pictures',
  'videos',
  'music',
  'appdata',
  'onedrive',
  'wps cloud files',
  'wpsdrive',
  'wechatprojects',
  'xwechat_files',
  'vmshare',
  'tools',
  '.dsh',
  '.claude',
  '.doubao',
  '.ssh',
  '.config',
  '.vscode',
  '.copilot',
  '.cc-switch',
  '.bailian',
  '.gitconfig',
  '.npmrc',
]

/**
 * 家目录下“连一级子项也要保护”的敏感目录：凭据、配置、我自己的作品。
 * 与 PROTECTED_CHILDREN 的区别是这里做前缀匹配，`~/.ssh/id_ed25519` 也算命中。
 */
const SENSITIVE_CHILDREN = [
  '.ssh',
  '.dsh',
  '.claude',
  '.doubao',
  '.config',
  '.copilot',
  '.cc-switch',
  '.bailian',
]

/** 凭据 / 密钥目录：只要删除目标落在里面（任意深度），一律拦。 */
const DEEP_SENSITIVE = ['.ssh', '.aws', '.gnupg']

/** Windows 系统目录：递归删除一律拦。 */
const SYSTEM_PREFIXES = [
  'c:/windows',
  'c:/program files',
  'c:/program files (x86)',
  'c:/programdata',
]

/**
 * `write` / `edit` 的目标保护：这些文件或目录被覆盖后，DSH 内部没有恢复手段。
 *
 * 只保护“系统级”的目标。工作区、`profiles/<name>/package.json` 故意不列进来，
 * 否则装插件 / 改提示词会先被自己的护栏拦住。
 */
const WRITE_DIR_PREFIXES = [
  `${HOME}/.dsh/sessions`,
  `${HOME}/.dsh/memory`,
  `${HOME}/.ssh`,
  `${HOME}/.aws`,
  `${HOME}/.gnupg`,
  'c:/windows',
  'c:/program files',
  'c:/program files (x86)',
]

/** 精确文件：必须原样保护的那几份（凭证、MCP token、全局指令）。 */
const WRITE_FILES = [
  `${HOME}/agents.md`,
  `${HOME}/.dsh/agents.md`,
  `${HOME}/.dsh/.credentials.yaml`,
  `${HOME}/.dsh/.github-mcp-token`,
  `${HOME}/.dsh/.mcd-mcp-token`,
  `${HOME}/.dsh/automation.env`,
]

/** 任意位置的凭证文件（`credentials.json` / `.credentials.yaml` 等）。 */
const WRITE_FILE_PATTERNS = [/(?:^|\/)\.?credentials(?:\.ya?ml|\.json)?$/]

/** 归一化：小写、折叠空白、反斜杠转正斜杠、去掉首尾空白。 */
function normalize(value) {
  return String(value ?? '')
    .replace(/\r/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase()
    .replace(/\\/g, '/')
}

function escapeRe(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** 正则按模式缓存：同一批受保护路径会在每次调用里反复编译，缓存后回到几十 µs。 */
const RE_CACHE = new Map()
function cachedRe(pattern) {
  let re = RE_CACHE.get(pattern)
  if (!re) {
    re = new RegExp(pattern, 'i')
    RE_CACHE.set(pattern, re)
  }
  return re
}

/** 整词匹配，避免 `c:/users/rose` 误命中 `c:/users/rose/documents`。 */
function hasToken(text, token) {
  if (!token) return false
  return cachedRe(
    `(?:^|[\\s"'(=/:])${escapeRe(token)}(?=(?:\\/+)?(?:$|[\\s"';|)&]))`,
  ).test(text)
}

/**
 * 前缀匹配：`base` 本身或它下面的任意路径也算命中。
 * `hasToken` 只匹配整词，所以 `~/.ssh/id_ed25519` 以前会漏。
 */
function hasPathPrefix(text, base) {
  if (!base) return false
  return cachedRe(`(?:^|[\\s"'(=])${escapeRe(base)}(?=/|$|[\\s"';|)&])`).test(text)
}

function hasHomeVar(segment) {
  return (
    /\$(?:home\b|\{home\}|\{env:home\}|env:userprofile\b|env:homepath\b)/i.test(segment) ||
    /%(?:userprofile|homepath)%/i.test(segment) ||
    /(?:^|[\s"'(=])~(?=[\s/"'()&|;]|$)/.test(segment) ||
    // AppData 只保护“整个目录”和 `/*`，放过 `$env:LOCALAPPDATA\Temp\...` 这类日常清理。
    /\$(?:env:)?(?:localappdata|appdata)\b(?=$|[\s"';|)&]|\/\*)/.test(segment)
  )
}

/** 根目录 / 盘符根 / 通配整盘。 */
function hasRootTarget(segment) {
  return (
    /(?:^|[\s"'(=])\/(?=[\s"';|)&]|$)/.test(segment) ||
    /(?:^|[\s"'(=])(?:\/\*|[a-z]:\/\*)(?=[\s"';|)&]|$)/.test(segment) ||
    /(?:^|[\s"'(=])[a-z]:\/(?=[\s"';|)&]|$)/.test(segment) ||
    /(?:^|[\s"'(=])\*(?=[\s"';|)&]|$)/.test(segment)
  )
}

/** 临时目录：删这里的内容是日常清理，真实日志里误拦最多的就是它们。 */
const TEMP_DIRS = [`${HOME}/appdata/local/temp`, 'c:/windows/temp']

function isTempPath(path) {
  return TEMP_DIRS.some((dir) => path === dir || path.startsWith(`${dir}/`))
}

/** 单层变量表：`$name = 'value'` / `"value"` / value。只跟一层，够覆盖诺亚方舟的写法。 */
function varTable(command) {
  const table = new Map()
  const text = String(command ?? '')
  for (const match of text.matchAll(/\$([a-z_][\w:]*)\s*=\s*("[^"]*"|'[^']*'|[^;\n|]+)/gi)) {
    table.set(match[1].toLowerCase(), match[2].trim().replace(/^["']|["']$/g, ''))
  }
  // `foreach ($d in (Get-ChildItem $home)) { Remove-Item $d }`：循环变量继承被遍历对象的危险程度。
  for (const match of text.matchAll(/foreach\s*\(\s*\$([a-z_][\w:]*)\s+in\s+([^)]*)\)/gi)) {
    const source = match[2].match(/(?:get-childitem|gci|ls|dir|get-item|gi)\s+("[^"]*"|'[^']*'|[^\s)]+)/i)
    const target = source ? expandPath(source[1], table) : ''
    if (evaluateTarget(target) === 'block') table.set(match[1].toLowerCase(), target)
  }
  // `$d = Get-ChildItem $HOME; $d | Remove-Item ...`：把集合变量的来源路径记下来，
  // 否则管道那一侧只看到一个光秃秃的 `$d`，目标就丢了。
  for (const match of text.matchAll(/\$([a-z_][\w:]*)\s*=\s*(?:get-childitem|gci|ls|dir|get-item|gi)\b([^;|\n]*)/gi)) {
    const arg = match[2].match(/("[^"]*"|'[^']*'|[^\s)]+)/)
    if (!arg || arg[1].startsWith('-')) continue
    const target = expandPath(arg[1], table)
    if (target) table.set(match[1].toLowerCase(), target)
  }
  return table
}

/** 展开一个删除目标：去引号、展开家目录写法与单层变量、把 MSYS 的 `/c/` 还原成 `c:/`。 */
function expandPath(raw, table) {
  let text = normalize(String(raw ?? ''))
  text = text.replace(/^[("'\s]+|[)"'\s]+$/g, '')
  text = text.replace(/^\/\/\?\//, '') // `\\?\C:\...` 设备路径前缀
  text = text.replace(/^(?:-literalpath|-path|-lp)\s+/, '')
  const expandHome = (value) =>
    value
      .replace(/^~(?=\/|$)/, HOME)
      .replace(
        /^(?:\$(?:env:)?(?:home|userprofile|homepath)|\$\(\s*\$env:userprofile\s*\)|%(?:userprofile|homepath)%)/,
        HOME,
      )
  text = expandHome(text)
  const variable = text.match(/^\$([a-z_][\w:]*)\b/)
  if (variable) {
    const value = table.get(variable[1].toLowerCase())
    // 变量值本身也可能是 `$env:USERPROFILE\...`，替换完再展开一次家目录。
    if (value !== undefined) text = expandHome(`${normalize(value).replace(/^["']|["']$/g, '')}${text.slice(variable[0].length)}`)
  }
  text = text.replace(/^\/([a-z])\//, '$1:/')
  // 折叠 `.` 与 `..`：`~/Desktop/..` 就是家目录本身，别让目标解析绕过保护。
  text = text.replace(/\/\.(?=\/|$)/g, '')
  let previous
  do {
    previous = text
    text = text.replace(/\/[^/]+\/\.\.(?=\/|$)/g, '')
  } while (text !== previous && text.length > 0)
  return text.replace(/\/+$/, '').replace(/\/{2,}/g, '/')
}

/**
 * 判定“删除这个目标”有多危险。
 * 关键区别：家目录根本身 / 敏感子目录任意深度 → block；家目录下的一级数据目录整体 → block；
 * 更深的路径（`~/Desktop/x.png`、`%TEMP%\a.mjs`）→ allow，日常清理几乎都落在这一层。
 * @returns {'block'|'ask'|'allow'}
 */
function evaluateTarget(path) {
  if (!path) return 'allow'
  // `[Environment]::GetFolderPath('UserProfile')` 这类运行时取值，静态看不到结果，按家目录处理。
  if (/getfolderpath|specialfolders?|environment::/.test(path)) return 'block'
  if (path.includes('$') || path.includes('%')) return hasHomeVar(path) ? 'block' : 'allow'
  if (isTempPath(path)) return 'allow'
  if (path === HOME || path === `${HOME}/*` || path === `${HOME}*`) return 'block'
  if (path.startsWith(`${HOME}/`)) {
    const relative = path.slice(HOME.length + 1)
    if (relative === '*' || relative === '/*') return 'block'
    const parts = relative.split('/')
    const first = parts[0]
    const depth = parts.length
    // 家目录一级的通配（`~/Doc*`、`~/*`）可能命中受保护目录，按整体删除处理。
    if (depth === 1 && /[*?]/.test(first)) return 'block'
    // 凭据 / 密钥目录：任意深度都不许删。
    if (DEEP_SENSITIVE.includes(first)) return 'block'
    if (SENSITIVE_CHILDREN.includes(first)) {
      if (depth === 1) return 'block'
      // `.dsh` 的会话、记忆、profile 再深一层仍是 DSH 的命根子；更深的构建产物放行。
      if (first === '.dsh') {
        if (['sessions', 'memory'].includes(parts[1])) return 'block'
        return depth <= 2 ? 'block' : 'allow'
      }
      return depth === 2 ? 'ask' : 'allow'
    }
    if (PROTECTED_CHILDREN.includes(first)) {
      if (depth === 1) return 'block'
      return depth === 2 && relative.endsWith('/*') ? 'ask' : 'allow'
    }
    return 'allow'
  }
  for (const extra of EXTRA_PROTECTED) {
    if (path === extra) return 'block'
    if (path.startsWith(`${extra}/`)) return path.slice(extra.length + 1).includes('/') ? 'allow' : 'block'
  }
  for (const prefix of SYSTEM_PREFIXES) {
    if (path === prefix || path.startsWith(`${prefix}/`)) return 'block'
  }
  if (/^[a-z]:\/?$/.test(path) || path === '/' || path === '*' || /^[a-z]:\/\*$/.test(path)) return 'block'
  if (/^c:\/users\/[^/]+$/.test(path)) return 'block'
  if (/^\/mnt\/[a-z]\/?$/.test(path)) return 'block'
  if (/^\/mnt\/[a-z]\/(?:users|windows|program)/.test(path)) return 'block'
  for (const root of ['/etc', '/usr', '/var', '/boot', '/root', '/opt', '/srv']) {
    if (path === root || path.startsWith(`${root}/`)) return 'block'
  }
  if (/^\/(?:home|users)\/[^/]+$/.test(path)) return 'block'
  return 'allow'
}

/** 判断一段文本里是否直接出现了“家目录根 / 敏感子目录 / 系统目录”的字面量。 */
function containsProtectedRoot(text) {
  if (!text) return false
  if (isTempPath(text)) return false
  if (cachedRe(`(?:^|[\\s"'(=])${escapeRe(HOME)}(?![a-z0-9_.\\/-])`).test(text)) return true
  for (const child of SENSITIVE_CHILDREN) {
    if (hasPathPrefix(text, `${HOME}/${child}`)) return true
  }
  for (const extra of EXTRA_PROTECTED) {
    if (hasToken(text, extra)) return true
  }
  for (const prefix of SYSTEM_PREFIXES) {
    if (cachedRe(`(?:^|[\\s"'(=])${escapeRe(prefix)}(?=/|\\*|$|[\\s"';|)&])`).test(text)) return true
  }
  return false
}

/** 从一条删除语句里取出“动词 + 目标参数”，`-Recurse` 之类的开关不算目标。 */
function deleteArgs(segment) {
  const verb = deleteVerb(segment)
  if (!verb) return { verb: '', args: [] }
  const text = stripWrappers(segment)
  const heads = {
    'remove-item': /^(?:remove-item|ri)\b/i,
    del: /^(?:del|erase)\b/i,
    rmdir: /^(?:rmdir|rd)\b/i,
    rm: /^rm\b/i,
    shred: /^(?:shred|sdelete)\b/i,
    find: /^find\b/i,
    dotnet: /^(?:\[(?:system\.)?io\.(?:directory|file)\]\s*::\s*delete)/i,
  }
  const rest = text.replace(heads[verb] ?? /^/, '')
  const args = []
  for (const match of rest.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)) {
    const token = (match[1] ?? match[2] ?? match[3] ?? '').trim()
    if (!token || /^-[a-z]+$/i.test(token) || /^(?:\.|\.\.|\d+)$/.test(token)) continue
    args.push(token)
  }
  return { verb, args }
}

/** 家目录、家目录一级子目录、其他用户目录、系统目录。 */
function protectedLiteral(segment) {
  if (hasToken(segment, HOME)) return HOME
  if (HOME && (segment.includes(`${HOME}/*`) || segment.includes(`${HOME}*`) || segment.includes(`${HOME}?`))) {
    return `${HOME}/*`
  }
  for (const child of PROTECTED_CHILDREN) {
    if (hasToken(segment, `${HOME}/${child}`)) return `${HOME}/${child}`
    if (HOME && (segment.includes(`${HOME}/${child}/*`) || segment.includes(`${HOME}/${child}*`))) {
      return `${HOME}/${child}/*`
    }
  }
  // 敏感目录连子项一起保护：`~/.ssh/id_ed25519`、`~/.dsh/memory` 都算。
  for (const child of SENSITIVE_CHILDREN) {
    if (hasPathPrefix(segment, `${HOME}/${child}`)) return `${HOME}/${child}`
  }
  // 其他受保护根也保护一级子目录：删掉 `C:\DSH Plugin\dsh-destructive-guard` 整个仓库同样致命。
  for (const extra of EXTRA_PROTECTED) {
    if (hasToken(segment, extra)) return extra
    const child = cachedRe(`(?:^|[\\s"'(=])${escapeRe(extra)}/[^/\\s"']+(?=$|[\\s"';|)&])`)
    if (child.test(segment)) return `${extra}/<child>`
  }
  // 家目录下任何带通配符的递归删除都按“可能命中受保护目录”处理。
  // 只认 `*`：`?` 在 PowerShell / C# / 三元表达式里太常见，会把普通脚本判成通配删除。
  if (HOME && segment.includes(`${HOME}/`) && /\*/.test(segment)) return `${HOME}/<wildcard>`
  if (/(?:^|[\s"'(=])\/mnt\/[a-z]\/?(?=$|[\s"';|)&])/.test(segment)) return '/mnt/<drive>'
  if (/(?:^|[\s"'(=])\/mnt\/[a-z]\/users(?:\/[^/\s"']+)?(?:\/\*)?(?=$|[\s"';|)&])/.test(segment)) return '/mnt/<drive>/users'
  if (/(?:^|[\s"'(=])\/mnt\/[a-z]\/users\/[^/\s"']+\/[^/\s"']+(?:\/\*)?(?=$|[\s"';|)&])/.test(segment)) {
    return '/mnt/<drive>/users/<user>/<dir>'
  }
  for (const root of ['/etc', '/usr', '/var', '/boot', '/root', '/opt', '/srv', '/home']) {
    if (hasToken(segment, root)) return root
  }
  if (/(?:^|[\s"'(=])\/home\/[^/\s"']+(?:\/\*)?(?=$|[\s"';|)&])/.test(segment)) return '/home/<user>'
  if (/(?:^|[\s"'(=])c:\/users(?:\/\*)?(?=$|[\s"';|)&])/.test(segment)) return 'c:/users'
  if (/(?:^|[\s"'(=])c:\/users\/[^/\s"']+(?:\/\*)?(?=$|[\s"';|)&])/.test(segment)) return 'c:/users/<user>'
  for (const prefix of SYSTEM_PREFIXES) {
    if (new RegExp(`(?:^|[\\s"'(=])${escapeRe(prefix)}(?:/|\\*|$)`).test(segment)) return prefix
  }
  return ''
}

/** 去掉 `cmd /c`、`powershell -Command`、`sudo` 等包装，露出真正的命令词。 */
function stripWrappers(segment) {
  let text = segment.trim()
  const wrapper =
    /^(?:sudo|doas|cmd(?:\.exe)?\s+\/c|powershell(?:\.exe)?\s+(?:-command|-c)|pwsh(?:\.exe)?\s+(?:-command|-c)|bash\s+-c|sh\s+-c|call)\s+/
  // PowerShell 控制流块：`if (Test-Path $home) { Remove-Item ... }` 先剥掉块头。
  const controlFlow =
    /^(?:if|elseif|while|for|foreach|switch|try|catch|finally|do|begin|process|end|trap)\b[^{}]*\{\s*/
  for (let index = 0; index < 8; index += 1) {
    const previous = text
    text = text.replace(/^[&.{("'\s]+/, '').replace(/[)}}\s]+$/, '')
    text = text.replace(wrapper, '').replace(controlFlow, '').trim()
    if (text === previous) break
  }
  return text
}

/**
 * 按 `;` / `&&` / `||` / 管道 / 换行切段（先切再归一化，保住换行边界）。
 * 括号内的 `;`、`|` 不切：`for ($i = 0; $i -lt 3; $i++) { Remove-Item ... }` 要留在同一段里，
 * 否则 `for` 头被切成碎片，块里的删除词永远露不出段首。
 */
function splitSegments(command) {
  const text = String(command ?? '').replace(/\r\n?/g, '\n')
  // 常见命令没有括号，直接正则切，省掉逐字符扫描。
  if (!/[()]/.test(text)) {
    return text.split(/[\n;]|&&|\|\||\|/).map((part) => normalize(part)).filter(Boolean)
  }
  const parts = []
  let depth = 0
  let buffer = ''
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    if (char === '(') depth += 1
    else if (char === ')') depth = Math.max(0, depth - 1)

    if (depth === 0 && (char === '\n' || char === ';')) {
      parts.push(buffer)
      buffer = ''
      continue
    }
    if (depth === 0 && (text.startsWith('&&', index) || text.startsWith('||', index))) {
      parts.push(buffer)
      buffer = ''
      index += 1
      continue
    }
    if (depth === 0 && char === '|') {
      parts.push(buffer)
      buffer = ''
      continue
    }
    buffer += char
  }
  parts.push(buffer)
  return parts.map((part) => normalize(part)).filter(Boolean)
}

/**
 * 按语句切（`\n` / `;` / `&&` / `||`），保留 `|`。
 * 管道判定必须限制在同一条语句内：`whole` 已经折叠了换行，跨句匹配会把
 * 「上一句的 `| Out-String`」和「下一句的 `Remove-Item`」拼成假管道（真实误报过）。
 */
function splitStatements(command) {
  const text = String(command ?? '').replace(/\r\n?/g, '\n')
  return text.split(/[\n;]|&&|\|\|/).map((part) => normalize(part)).filter(Boolean)
}

function deleteVerb(segment) {
  const text = stripWrappers(segment)
  if (/^\[(?:system\.)?io\.(?:directory|file)\]\s*::\s*delete\b/.test(text)) return 'dotnet'
  if (/^(?:remove-item|ri)\b/.test(text)) return 'remove-item'
  if (/^(?:del|erase)\b/.test(text)) return 'del'
  if (/^(?:rmdir|rd)\b/.test(text)) return 'rmdir'
  if (/^rm\b/.test(text)) return 'rm'
  if (/^find\b.*\s-delete\b/.test(text)) return 'find'
  if (/^(?:shred|sdelete)\b/.test(text)) return 'shred'
  return ''
}

function isRecursive(verb, segment) {
  if (verb === 'remove-item') return /(?:^|\s)-recurse\b|(?:^|\s)-r\b/.test(segment)
  if (verb === 'del' || verb === 'rmdir') return /(?:^|\s)\/s\b/.test(segment)
  if (verb === 'rm') return /(?:^|\s)-[a-z]*r[a-z]*\b/.test(segment)
  if (verb === 'find' || verb === 'dotnet') return true
  return false
}

/** 读取类命令：只有它们出现在命令里，才去判“是不是在读秘密文件”。 */
const READ_VERBS = /(?:^|[\s;&|(])(?:cat|type|more|less|head|tail|get-content|gc|select-string|sls|grep|rg|string|open|read)\b/i

/** 秘密文件：读出来就可能被外传，比删掉更难补救。 */
const SECRET_PATTERNS = [
  /(?:^|\/)\.env(?:\.[a-z0-9]+)*$/, // .env / .env.local，`.env.example` 单独放行
  /(?:^|\/)\.ssh\//,
  /(?:^|\/)\.aws\/(?:credentials|config)$/,
  /(?:^|\/)\.gnupg\/(?:.*\.key|private-keys.*)$/,
  /(?:^|\/)\.netrc$/,
  /(?:^|\/)\.git-credentials$/,
  /(?:^|\/)\.npmrc$/,
  /(?:^|\/)\.config\/gh\/hosts\.yml$/,
  /(?:^|\/)\.dsh\/\.credentials\.(?:ya?ml|json)$/,
  /(?:^|\/)\.dsh\/\.(?:github|mcd)-mcp-token$/,
  /(?:^|\/)\.dsh\/automation\.env$/,
  /(?:^|\/)(?:id_rsa|id_ed25519|id_ecdsa)(?:\.pub)?$/,
  /(?:^|\/)[^/\s]+\.(?:pem|key|pfx|p12)$/,
]

function secretTarget(segment, table) {
  const tokens = segment.match(/"[^"]*"|'[^']*'|\S+/g) ?? []
  for (const raw of tokens) {
    const token = expandPath(raw, table)
    if (!token || /^[a-z]+$/i.test(token)) continue
    if (/\.env\.example$/.test(token)) continue
    if (SECRET_PATTERNS.some((pattern) => pattern.test(token))) return token
  }
  return ''
}

/**
 * 判定单个文件路径是否属于秘密文件（给 `read` 工具用）。
 * @param {string} rawPath
 * @returns {boolean}
 */
export function isSecretPath(rawPath) {
  const token = expandPath(rawPath, new Map())
  if (!token || /\.env\.example$/.test(token)) return false
  return SECRET_PATTERNS.some((pattern) => pattern.test(token))
}

function block(rule, reason) {  return { verdict: 'block', rule, reason: `[dsh-guard:${rule}] ${reason}` }
}

function ask(rule, reason) {
  return { verdict: 'ask', rule, reason: `[dsh-guard:${rule}] ${reason}` }
}

/**
 * 判定一条 shell 命令。
 * @param {string} command 原始命令字符串。
 * @returns {{verdict:'block'|'ask'|'allow', rule?:string, reason?:string}}
 */
export function classify(command) {
  const whole = normalize(command)
  if (!whole) return { verdict: 'allow' }
  const vars = varTable(command)

  // ---- 不可逆：磁盘 / 恢复 / 日志 / 注册表 / 安全软件 ----
  if (/\b(?:vssadmin|wbadmin|diskshadow)\b/.test(whole)) {
    if (
      /vssadmin\b[^;]*(?:delete\s+shadows|resize\s+shadowstorage)/.test(whole) ||
      /wbadmin\b[^;]*delete\s+(?:catalog|systemstatebackup)/.test(whole) ||
      /diskshadow\b[^;]*delete\s+shadows/.test(whole)
    ) {
      return block('RECOVERY-INHIBIT', '删除卷影副本 / 备份目录会让数据无法恢复（勒索软件 T1490 的标志动作）。请交给用户手动处理。')
    }
  }
  if (/\bwmic(?:\.exe)?\b[^;]*shadowcopy[^;]*delete/.test(whole)) {
    return block('RECOVERY-INHIBIT', 'wmic shadowcopy delete 会删除卷影副本，让数据无法恢复（T1490）。')
  }
  if (/\bbcdedit(?:\.exe)?\b/.test(whole) && /(?:delete|recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/.test(whole)) {
    return block('BOOT-CONFIG', '修改启动配置 / 关闭恢复会破坏系统自修复能力。请交给用户手动处理。')
  }
  if (/\breagentc(?:\.exe)?\s+\/disable\b/.test(whole) || /\bdisable-computerrestore\b/.test(whole)) {
    return block('RECOVERY-INHIBIT', '关闭系统还原 / WinRE 属于不可逆的恢复能力破坏。')
  }
  if (
    /\bformat(?:\.com)?\s+[a-z]:/.test(whole) ||
    /\b(?:format-volume|clear-disk|initialize-disk|remove-partition)\b/.test(whole) ||
    (/\bdiskpart\b/.test(whole) && /\b(?:clean|delete)\b/.test(whole)) ||
    /\bdd\b[^;]*\bof=\/dev\//.test(whole) ||
    /\b(?:mkfs(?:\.\w+)?|wipefs)\b/.test(whole)
  ) {
    return block('DISK-WIPE', '磁盘 / 分区级破坏会直接抹掉整块盘。请交给用户手动处理。')
  }
  if (/\bcipher(?:\.exe)?\s+\/w/.test(whole)) {
    return block('DATA-WIPE', 'cipher /w 会覆写磁盘空闲空间，让被删数据无法恢复。')
  }
  if (/\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b/.test(whole) || /\bclear-eventlog\b/.test(whole) || /\bauditpol(?:\.exe)?\s+\/clear/.test(whole)) {
    return block('LOG-WIPE', '清空事件日志 / 审计日志会破坏事后取证。')
  }
  if (/\bfsutil(?:\.exe)?\b[^;]*deletejournal/.test(whole)) {
    return block('LOG-WIPE', '删除 USN 日志会破坏文件删除痕迹。')
  }
  if (/\breg(?:\.exe)?\s+delete\s+["']?(?:hklm|hku|hkcr|hkcc)\b/.test(whole)) {
    return block('REGISTRY-WIPE', '删除 HKLM/HKU 注册表项可能让系统或软件无法启动。')
  }
  if (/\breg(?:\.exe)?\s+delete\s+["'\\]*hkcu\b/.test(whole)) {
    return ask('REGISTRY-USER', '删除 HKCU 项可能让当前用户的软件配置失效。')
  }
  if (/\btakeown(?:\.exe)?\s+\/f\s+[a-z]:\/?(?=\s|$)/.test(whole) || /\bicacls(?:\.exe)?\s+[a-z]:\/?(?=\s|$)[^;]*\/reset/.test(whole)) {
    return block('ACL-TAKEOVER', '夺取盘根 / 系统目录所有权或重置 ACL 会破坏系统权限。')
  }
  // 只有“变更型”的 ACL 操作才算接管；纯查询（`icacls "C:\Program Files\Bandizip"`）放行。
  if (
    (/\btakeown(?:\.exe)?\b/.test(whole) && /\s\/f\b/.test(whole)) ||
    (/\bicacls(?:\.exe)?\b/.test(whole) && /\/(?:reset|grant|deny|setowner|inheritance)\b/.test(whole))
  ) {
    if (protectedLiteral(whole) || hasHomeVar(whole)) {
      return block('ACL-TAKEOVER', '夺取家目录 / 受保护目录的所有权或重置 ACL，会让后续删除畅通无阻。')
    }
  }
  if (/\bsc(?:\.exe)?\s+delete\b/.test(whole) || /\bnet(?:\.exe)?\s+user\s+\S+\s+\/delete\b/.test(whole) || /\bnet(?:\.exe)?\s+localgroup\s+administrators\b[^;]*\/delete/.test(whole)) {
    return block('SERVICE-ACCOUNT', '删除系统服务 / 本地账户 / 管理员组成员需要人工确认。')
  }
  if (
    /\bset-mppreference\b[^;]*-disable/.test(whole) ||
    /\badd-mppreference\b[^;]*-exclusionpath/.test(whole) ||
    /\bnetsh(?:\.exe)?\s+advfirewall\b[^;]*state\s+off/.test(whole) ||
    /\bmanage-bde(?:\.exe)?\b[^;]*-off/.test(whole)
  ) {
    return block('SECURITY-TAMPER', '关闭杀毒 / 防火墙 / 磁盘加密属于安全配置破坏。')
  }
  if (/\bwsl(?:\.exe)?\s+--unregister\b/.test(whole)) {
    return block('VM-DESTROY', 'wsl --unregister 会删除整个发行版及其文件。')
  }
  if (/\bbootrec(?:\.exe)?\b/.test(whole) && /\/(?:fixmbr|fixboot|rebuildbcd)\b/.test(whole)) {
    return block('BOOT-CONFIG', 'bootrec 修复 / 重建引导会改写磁盘引导结构，必须由用户手动执行。')
  }
  if (/\bchmod\s+-r\s+[0-7]{3,4}\s+\/(?=\s|$)/.test(whole) || /\bchown\s+-r\s+[^;]+\s+\/(?=\s|$)/.test(whole)) {
    return block('FS-PERMISSIONS', '递归改根目录权限 / 属主会让系统或 WSL 无法使用。')
  }
  if (/:\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:[^}]*&[^}]*\}\s*;\s*:/.test(whole)) {
    return block('FORK-BOMB', 'fork bomb 会耗尽进程表。')
  }

  // 管道式批量删除：`Get-ChildItem C:\Users\ROSE -Recurse | Remove-Item -Force`。
  // 逐语句判（不跨换行），并且只认“生产者目标本身危险”的管道：
  // 删 `~/Desktop` 整批仍拦；删项目构建目录、删 `%TEMP%` 明细放行。
  // `cd $HOME; Get-ChildItem | Remove-Item -Recurse -Force`：生产者不带路径参数，
  // 但工作目录已经被切到受保护目录，列出来的就是家目录里的东西。
  const cdProtected = splitSegments(command).some((segment) => {
    const match = stripWrappers(segment).match(/^(?:cd|set-location|sl|pushd)\s+("[^"]*"|'[^']*'|\S+)/)
    return Boolean(match) && evaluateTarget(expandPath(match[1], vars)) === 'block'
  })
  for (const statement of splitStatements(command)) {
    const parts = statement.split('|')
    if (parts.length < 2) continue
    const last = stripWrappers(parts[parts.length - 1])
    if (!/^(?:remove-item|ri|del|erase|rm|rmdir|rd)\b/.test(last)) continue
    const producer = parts.slice(0, -1).join('|')
    const produced = producer.match(/(?:get-childitem|gci|ls|dir|get-item|gi)\s+(?!-)(?:"([^"]*)"|'([^']*)'|([^\s|]+))/)
    const target = produced ? expandPath(produced[1] ?? produced[2] ?? produced[3], vars) : ''
    const level = evaluateTarget(target)
    if (level === 'block') {
      return block('FS-HOME', `管道批量删除指向受保护路径（${target}）。请改用具体的构建 / 临时目录，并由用户手动确认。`)
    }
    if (level === 'ask') {
      return ask('FS-HOME', `管道将清空受保护目录（${target}），请先确认范围。`)
    }
    // 生产者是存过危险路径的变量（`$d = Get-ChildItem $HOME; $d | Remove-Item`）。
    if (!produced) {
      const variable = producer.match(/\$([a-z_][\w:]*)\s*$/)
      const stored = variable ? vars.get(variable[1].toLowerCase()) : ''
      if (stored && evaluateTarget(expandPath(stored, vars)) === 'block') {
        return block('FS-HOME', `管道批量删除的是变量 ${variable[0]}，它的来源是受保护路径（${stored}）。`)
      }
    }
    // 生产者是裸的家目录变量（`ls $home | ri`）时没有路径参数，单独认一次。
    if (!produced && /(?:^|[\s=(])\$(?:home|env:userprofile|env:homepath)\b(?!\s*[/\\])/.test(producer)) {
      return block('FS-HOME', '管道批量删除指向家目录根（$home）。这与诺亚方舟事故是同一类操作。')
    }
    if (!produced && cdProtected && /\b(?:get-childitem|gci|ls|dir|get-item|gi)\b/.test(producer)) {
      return block('FS-HOME', '工作目录已切到受保护目录，管道批量删除等价于清空该目录。')
    }
  }

  // WSL 里再套一层 rm：wsl bash -c "rm -rf /mnt/c/Users/ROSE"
  if (
    /\bwsl(?:\.exe)?\b/.test(whole) &&
    /\brm\s+-[a-z]*r[a-z]*/.test(whole) &&
    /\/mnt\/[a-z]\/(?:users|windows|program)/.test(whole)
  ) {
    return block('FS-HOME', 'WSL 里对 /mnt/c 的用户目录 / 系统目录做递归删除。')
  }

  // 包装器绕过：Start-Process / iex / runas / Start-Job 里再拼删除命令。
  // 只有里面真的出现“家目录根 / 敏感子目录 / 系统目录”才拦：普通软件的启动脚本
  // （Everything 之类，正文里带一堆 `C:\Users\ROSE\AppData\...`）不再误伤。
  if (
    /\b(?:start-process|start-job|start-threadjob|invoke-expression|invoke-command|runas)\b/.test(whole) &&
    /\b(?:remove-item|del|erase|rm|rmdir|format|vssadmin)\b/.test(whole) &&
    (containsProtectedRoot(whole) || hasHomeVar(whole))
  ) {
    return block('WRAPPED-DESTRUCTIVE', '在包装器 / 表达式里拼接删除命令，且目标落在受保护路径上。')
  }

  // 内联解释器删除：只看 `-c` / `-e` 之后的代码段，
  // 避免 `cd C:\Users\ROSE\Desktop\...; python -c "os.remove('q601_*.png')"` 因前置路径误拦。
  const inlineStart = whole.search(/\s-(?:c|e)\s/)
  const inline = inlineStart >= 0 ? whole.slice(inlineStart) : ''
  if (
    inline &&
    /\b(?:python|py|python3)(?:\.exe)?\s+-c\b/.test(whole) &&
    /(?:shutil\.rmtree|os\.(?:remove|unlink|rmdir)|pathlib[^;]*unlink|os\.system|subprocess)/.test(inline) &&
    containsProtectedRoot(inline)
  ) {
    return block('SCRIPT-DELETE', '内联 Python 删除调用指向受保护路径。')
  }
  if (
    inline &&
    /\bnode(?:\.exe)?\s+-e\b/.test(whole) &&
    /(?:rmsync|rmdirsync|unlinksync|fs\.rm\b|child_process)/.test(inline) &&
    containsProtectedRoot(inline)
  ) {
    return block('SCRIPT-DELETE', '内联 Node 删除调用指向受保护路径。')
  }
  if (
    inline &&
    /\bperl(?:\.exe)?\s+-e\b/.test(whole) &&
    /(?:unlink|rmtree|system)/.test(inline) &&
    containsProtectedRoot(inline)
  ) {
    return block('SCRIPT-DELETE', '内联 Perl 删除调用指向受保护路径。')
  }

  // ---- 不透明 / 远程执行 ----
  // EncodedCommand 先尝试解码（UTF-16LE），解出无害命令就放行；解不出或解出危险命令才拦。
  // 必须在**原始命令**上取 base64：normalize 会转小写，base64 是大小写敏感的。
  const rawCommand = String(command ?? '')
  const encoded =
    rawCommand.match(/(?:^|\s)-{1,2}(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]{20,})/i) ??
    rawCommand.match(/\b(?:powershell|pwsh)(?:\.exe)?\s+-(?:e|en)\s+([A-Za-z0-9+/=]{20,})/i)
  if (encoded) {
    let decoded = ''
    try {
      decoded = Buffer.from(encoded[1], 'base64').toString('utf16le').replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '')
    } catch {
      decoded = ''
    }
    if (!decoded.trim()) {
      return block('ENCODED-CMD', 'EncodedCommand 无法解码为可读文本，可能隐藏任意删除操作。')
    }
    const inner = classify(decoded)
    if (inner.verdict !== 'allow') {
      return block('ENCODED-CMD', `EncodedCommand 解码后命中 ${inner.rule}：${decoded.slice(0, 160)}`)
    }
  }
  if (/(?:iwr|invoke-webrequest|irm|invoke-restmethod|curl|wget)\b[^|;]*\|\s*(?:iex|invoke-expression|sh|bash|pwsh|powershell)\b/.test(whole)) {
    return block('REMOTE-EXEC', '下载后直接管道执行远程代码，内容不可审查。')
  }
  if (/(?:iex|invoke-expression)\s*[\(\s][^;]*(?:downloadstring|invoke-webrequest|iwr|irm|curl|wget)/.test(whole)) {
    return block('REMOTE-EXEC', 'Invoke-Expression 执行下载内容，内容不可审查。')
  }
  if (/\bmshta(?:\.exe)?\s+https?:/.test(whole) || /\bregsvr32(?:\.exe)?\b[^;]*\/i:https?:/.test(whole) || /\brundll32(?:\.exe)?\b[^;]*javascript:/.test(whole)) {
    return block('LOLBAS', 'mshta / regsvr32 / rundll32 的远程执行是常见 LOLBAS 手法。')
  }

  // ---- 需要人工确认的“范围性”破坏 ----
  if (/\b(?:robocopy|rsync)\b/.test(whole) && /(?:--delete|\/mir\b)/.test(whole) && (protectedLiteral(whole) || hasHomeVar(whole))) {
    return ask('MIRROR-DELETE', '镜像同步到受保护目录可能删除目标端多余文件。')
  }
  if (/\bgit\s+reset\s+--hard\b/.test(whole)) return ask('GIT-DESTRUCTIVE', 'git reset --hard 会丢弃未提交改动。')
  if (/\bgit\s+clean\s+-[a-z]*[xdf]/.test(whole)) return ask('GIT-DESTRUCTIVE', 'git clean -x/-d/-f 会删除未跟踪文件。')
  if (/\bgit\s+push\b[^;]*--force/.test(whole)) return ask('GIT-DESTRUCTIVE', 'git push --force 会改写远端历史。')
  if (/\bdocker\s+(?:system|volume|image|container)\s+prune\b/.test(whole)) return ask('CONTAINER-PRUNE', 'docker prune 会删除容器 / 卷 / 镜像数据。')
  if (/\bkubectl\s+delete\b/.test(whole)) return ask('CLUSTER-DELETE', 'kubectl delete 会删除集群资源。')
  if (/\bterraform\s+destroy\b/.test(whole)) return ask('INFRA-DESTROY', 'terraform destroy 会销毁基础设施。')
  if (
    /\baws\s+s3\s+rb\b[^;]*--force/.test(whole) ||
    /\baws\s+s3\s+rm\b[^;]*--recursive/.test(whole) ||
    /\baws\s+ec2\s+terminate-instances\b/.test(whole) ||
    /\baws\s+iam\b[^;]*delete/.test(whole) ||
    /\bgcloud\s+(?:projects\s+delete|compute\s+instances\s+delete)\b/.test(whole) ||
    /\baz\s+(?:group|vm)\s+delete\b/.test(whole)
  ) {
    return ask('CLOUD-DESTROY', '云资源删除 / 终止需要人工确认，且可能不可恢复。')
  }
  if (/\bclear-recyclebin\b/.test(whole)) return ask('RECYCLE-BIN', '清空回收站会失去最后一道误删恢复手段。')
  if (/\bshutdown(?:\.exe)?\s+\/[rs]/.test(whole) || /\b(?:restart-computer|stop-computer)\b/.test(whole)) {
    return ask('POWER-STATE', '关机 / 重启会中断正在运行的任务。')
  }
  if (/\bwusa(?:\.exe)?\s+\/uninstall\b/.test(whole) || /\bdism(?:\.exe)?\b[^;]*\/remove-package/.test(whole)) {
    return ask('SYSTEM-COMPONENT', '卸载系统更新 / 组件可能让系统不稳定。')
  }
  if (/\bschtasks(?:\.exe)?\s+\/delete\b/.test(whole)) {
    return ask('SCHEDULE-DELETE', '删除计划任务可能移除备份 / 维护作业。')
  }
  if (/\bdrop\s+(?:database|schema|table)\b/.test(whole) || /\btruncate\s+table\b/.test(whole)) {
    return ask('DB-DESTRUCTIVE', 'DROP / TRUNCATE 会不可逆地删除数据库对象或数据。')
  }

  // ---- 秘密读取：删掉还能从备份恢复，读走再外传就收不回来了 ----
  if (READ_VERBS.test(whole)) {
    for (const segment of splitSegments(command)) {
      if (!READ_VERBS.test(segment)) continue
      const secret = secretTarget(segment, vars)
      if (secret) {
        return block('SECRET-READ', `读取凭据 / 密钥文件（${secret}）可能造成外泄。请由用户手动查看，或改用环境变量注入。`)
      }
    }
  }

  // ---- 文件系统递归删除：逐段判定 ----
  for (const segment of splitSegments(command)) {
    const { verb, args } = deleteArgs(segment)
    if (!verb) continue
    const recursive = isRecursive(verb, segment)

    // `C:\Users\ROSE\Documents\..\Desktop` 这类路径穿越
    if (
      recursive &&
      /(?:^|[\s"'(=/])\.\.(?:\/|$)/.test(segment) &&
      ((HOME && segment.includes(HOME)) || hasHomeVar(segment))
    ) {
      return block('FS-TRAVERSAL', '递归删除路径里含 .. 穿越，最终目标可能落回家目录。')
    }

    for (const arg of args) {
      const target = expandPath(arg, vars)
      const level = evaluateTarget(target)
      if (level === 'block') {
        return block(
          'FS-HOME',
          `删除指向受保护路径（${target || arg}）。这与诺亚方舟事故是同一类操作：先删家目录，再连带 .dsh/.claude/.doubao。请改用明确的临时目录，并由用户手动确认。`,
        )
      }
      if (level === 'ask') {
        return ask('FS-HOME', `将清空受保护目录（${target}）里的全部内容，请先确认范围。`)
      }
    }

    if (hasRootTarget(segment) && (recursive || verb === 'find' || verb === 'shred')) {
      return block('FS-ROOT', '递归删除指向根目录 / 盘符根 / 通配整盘。')
    }

    if (verb === 'find') return ask('FS-FIND-DELETE', 'find -delete 会批量删除匹配文件，请先确认目标范围。')
    if (verb === 'shred') return ask('FS-SHRED', 'shred 会覆写文件，删除后不可恢复。')

    if (recursive && /(?:^|[\s"'(=])\.\.?(?:\/)?(?=$|[\s"';|)&])/.test(segment)) {
      return ask('FS-CWD', '递归删除当前目录 / 上级目录会清空工作区内容。')
    }
  }

  return { verdict: 'allow' }
}

/**
 * 把工具参数里的路径归一化：去引号、展开 `~` / `$HOME` / `%USERPROFILE%`。
 * 只做字面展开，不访问文件系统。
 */
function expandTarget(raw) {
  let path = normalize(String(raw ?? ''))
  path = path.replace(/^file:\/\//, '').replace(/^["']|["']$/g, '')
  path = path.replace(/^(?:\$(?:env:)?(?:home|userprofile)|\$\(\s*\$env:userprofile\s*\)|%userprofile%)/, HOME)
  path = path.replace(/^~(?=\/|$)/, HOME)
  return path.replace(/\/{2,}/g, '/')
}

/**
 * 判定 `write` / `edit` / `apply_patch` / `ops_write_file` / `ops_edit_file` / `ops_remove`
 * 等文件写入的落点是否属于“覆盖或删除就不可恢复”的文件。
 * `apply_patch` 没有 `file_path`，从补丁头的 `*** Update File: <path>` 行取目标；
 * dsh-ops 的 copy/move 还带目标 `to`，源与目标都要检查。
 * @param {string} toolName 工具名，只用于文案。
 * @param {unknown} args 工具参数，认 `file_path` / `path` / `target` / `to` 与补丁正文。
 * @returns {{verdict:'block'|'allow', rule?:string, reason?:string}}
 */
export function classifyFileWrite(toolName, args) {
  const targets = []
  const single = args?.file_path ?? args?.path ?? args?.target
  if (single) targets.push(String(single))
  // dsh-ops 的 copy / move 有独立的 `to`；目标也可能落在受保护路径上。
  if (typeof args?.to === 'string' && args.to) targets.push(args.to)
  const patch = args?.patch ?? args?.input ?? args?.diff
  if (typeof patch === 'string' && patch) {
    for (const match of patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File:\s*(.+)$/gim)) {
      targets.push(match[1].trim())
    }
  }
  if (targets.length === 0) return { verdict: 'allow' }

  for (const target of targets) {
    const path = expandTarget(target)
    if (!path) continue
    const hit = WRITE_DIR_PREFIXES.find((base) => path === base || path.startsWith(`${base}/`))
      ?? WRITE_FILES.find((file) => path === file)
      ?? (WRITE_FILE_PATTERNS.some((pattern) => pattern.test(path)) ? 'credentials' : '')
    if (!hit) continue
    return block(
      'FS-PROTECTED',
      `${toolName} 将覆盖受保护文件（${target}）：会话日志 / 记忆 / 凭证 / 密钥 / 系统目录无法从 DSH 内部恢复。请先备份，并由用户手动修改。`,
    )
  }
  return { verdict: 'allow' }
}

/** 供状态页展示的规则清单（不含实现细节）。 */
export const RULES = [
  ['RECOVERY-INHIBIT', 'block', '删除卷影副本 / 备份目录 / 关闭系统还原'],
  ['BOOT-CONFIG', 'block', 'bcdedit 删除启动项 / 关闭恢复'],
  ['DISK-WIPE', 'block', 'format / diskpart clean / Clear-Disk / dd / mkfs'],
  ['DATA-WIPE', 'block', 'cipher /w 覆写空闲空间'],
  ['LOG-WIPE', 'block', 'wevtutil cl / auditpol /clear / USN 日志'],
  ['REGISTRY-WIPE', 'block', 'reg delete HKLM / HKU / HKCR / HKCC'],
  ['ACL-TAKEOVER', 'block', 'takeown / icacls 重置盘根或系统目录'],
  ['SERVICE-ACCOUNT', 'block', 'sc delete / net user /delete'],
  ['SECURITY-TAMPER', 'block', '关闭 Defender / 防火墙 / BitLocker'],
  ['VM-DESTROY', 'block', 'wsl --unregister'],
  ['ENCODED-CMD', 'block', 'EncodedCommand 等不可审查命令'],
  ['REMOTE-EXEC', 'block', '下载后管道执行 / iex 下载内容'],
  ['LOLBAS', 'block', 'mshta / regsvr32 / rundll32 远程执行'],
  ['WRAPPED-DESTRUCTIVE', 'block', '包装器 / 表达式里拼接删除命令'],
  ['SCRIPT-DELETE', 'block', '内联 Python / Node / Perl 删除受保护路径'],
  ['FS-HOME', 'block', '删除家目录 / 敏感子目录（.ssh/.dsh 等）/ 受保护根的子项'],
  ['SECRET-READ', 'block', '读取 .env / .ssh / 云凭据 / DSH 凭证等秘密文件'],
  ['FS-PROTECTED', 'block', 'write / edit 覆盖会话日志、记忆、凭证、密钥、系统目录'],
  ['FS-ROOT', 'block', '递归删除根目录 / 盘符根 / 通配整盘'],
  ['FS-PERMISSIONS', 'block', '递归修改根目录权限 / 属主'],
  ['FORK-BOMB', 'block', 'fork bomb'],
  ['GIT-DESTRUCTIVE', 'ask', 'git reset --hard / clean -xdf / push --force'],
  ['CONTAINER-PRUNE', 'ask', 'docker prune'],
  ['CLUSTER-DELETE', 'ask', 'kubectl delete'],
  ['INFRA-DESTROY', 'ask', 'terraform destroy'],
  ['CLOUD-DESTROY', 'ask', 'aws / gcloud / az 删除资源'],
  ['RECYCLE-BIN', 'ask', 'Clear-RecycleBin'],
  ['POWER-STATE', 'ask', '关机 / 重启'],
  ['SYSTEM-COMPONENT', 'ask', '卸载系统更新 / 组件'],
  ['SCHEDULE-DELETE', 'ask', '删除计划任务'],
  ['DB-DESTRUCTIVE', 'ask', 'DROP / TRUNCATE'],
  ['FS-FIND-DELETE', 'ask', 'find -delete'],
  ['FS-SHRED', 'ask', 'shred / sdelete'],
  ['FS-CWD', 'ask', 'rm -rf .'],
]

export const PROTECTED_ROOTS = [
  HOME,
  ...PROTECTED_CHILDREN.map((child) => `${HOME}/${child}`),
  ...SENSITIVE_CHILDREN.map((child) => `${HOME}/${child}`),
  ...EXTRA_PROTECTED,
  ...SYSTEM_PREFIXES,
].filter(Boolean)

/** `write` / `edit` 受保护目标的条数（状态页展示用）。 */
export const WRITE_PROTECTED_COUNT = WRITE_DIR_PREFIXES.length + WRITE_FILES.length + WRITE_FILE_PATTERNS.length

