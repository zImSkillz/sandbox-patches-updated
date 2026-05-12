/* 
    Modified version of sandbox-patches by ZeroDream-CN
    https://github.com/ZeroDream-CN/sandbox-patches/
    https://github.com/ZeroDream-CN/

    modified to work with latest fivem artifacts, it only needs to be allowed to use unsafe child process
    server cfg: add_unsafe_child_process_permission "script_name"
*/

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync, spawn, spawnSync } = require('child_process');

const IS_WIN = process.platform === 'win32'; // only windows and linux are supported for fivem, we need the platform so we can execute the right command

function _run(cmd, capture = false) {
    try {
        const output = execSync(cmd, {
            encoding: 'utf8',
            timeout: 30_000,
            windowsHide: true,
            stdio: capture ? 'pipe' : undefined,
        });
        return { success: true, output: output ?? '' };
    } catch (err) {
        return { success: false, output: err instanceof Error ? err.message : String(err) };
    }
}

const _quote = (p) => IS_WIN ? `"${p.replace(/"/g, '""')}"` : `'${p.replace(/'/g, "'\\''")}'`;
const _normalize = (p) => IS_WIN ? p.replace(/\//g, '\\') : p;

function _exists(p, psType, shFlag) {
    const cmd = IS_WIN ? `powershell -Command "if (Test-Path -LiteralPath '${p.replace(/'/g, "''")}' -PathType ${psType}) { Write-Output 'EXISTS' } else { Write-Output 'NOTEXISTS' }"` : `[ -${shFlag} ${_quote(p)} ] && echo EXISTS || echo NOTEXISTS`;
    const result = _run(cmd, true);
    return result.success && result.output.trim() === 'EXISTS';
}

function _ensureDir(filePath) {
    const q = _quote(path.dirname(filePath));
    return _run(IS_WIN ? `if not exist ${q} mkdir ${q}` : `mkdir -p ${q}`, true);
}

function _writeToDisk(targetPath, data) {
    const tmp = path.join(os.tmpdir(), `sb_fix_${process.pid}_${Date.now()}.tmp`);
    try {
        fs.writeFileSync(tmp, data);

        const tq = _quote(tmp);
        const pq = _quote(targetPath);
        const result = IS_WIN ? _run(`move /Y ${tq} ${pq}`) : _run(`mv -f ${tq} ${pq}`);

        return result;
    } catch (err) {
        try { fs.unlinkSync(tmp); } catch (_) {}
        return { success: false, output: err instanceof Error ? err.message : String(err) };
    }
}

function _readFileBuffer(filePath) {
    const pq = _quote(filePath);
    try {
        const buf = execSync(IS_WIN ? `type ${pq}` : `cat ${pq}`, {
            encoding: 'buffer',
            timeout: 30_000,
            windowsHide: true,
            stdio: 'pipe',
        });

        return buf;
    } catch (_) {
        return null;
    }
}

class LuaIO {
    constructor() {
        this.fileHandles = new Map();
        this.processData = new Map();
        this.nextHandle = 1;
    }

    open(filename, mode) {
        mode = mode || 'r';
        const filePath = _normalize(String(filename));

        if (mode === 'w' || mode === 'w+') {
            const handle = this.nextHandle++;
            this.fileHandles.set(handle, {
                path: filePath,
                mode,
                position: 0,
                buffer: Buffer.alloc(0),
                dirty: false,
            });
            return handle;
        }

        if ((mode === 'r' || mode === 'r+') && !_exists(filePath, 'Leaf', 'f')) {
            return null;
        }

        let buffer = Buffer.alloc(0);
        if (_exists(filePath, 'Leaf', 'f')) {
            const raw = _readFileBuffer(filePath);
            if (raw) buffer = raw;
        }

        const handle = this.nextHandle++;
        this.fileHandles.set(handle, {
            path: filePath,
            mode,
            position: mode.includes('a') ? buffer.length : 0,
            buffer,
            dirty: false,
        });
        return handle;
    }

    close(handle) {
        //console.log("Close", this.fileHandles.has(handle), this.processData.has(handle), handle)
        if (this.fileHandles.has(handle)) {
            this._flush(handle);
            this.fileHandles.delete(handle);
            return true;
        }
        if (this.processData.has(handle)) {
            this.processData.delete(handle);
            return true;
        }

        return false;
    }

    _flush(handle) {
        const info = this.fileHandles.get(handle);
        if (!info || !info.dirty) return true;

        _ensureDir(info.path);
        
        const result = _writeToDisk(info.path, info.buffer);
        
        info.dirty = false;
        return result.success;
    }

    flush(handle) {
        return this._flush(handle);
    }

    read(handle, format) {
        if (this.processData.has(handle)) {
            const data = this.processData.get(handle).stdout || '';
            return 'hex:' + Buffer.from(data).toString('hex');
        }

        if (!this.fileHandles.has(handle)) return null;
        const info = this.fileHandles.get(handle);
        format = format || '*l';

        if (format === '*a' || format === '*all') {
            const slice = info.buffer.slice(info.position);
            info.position = info.buffer.length;
            return 'hex:' + slice.toString('hex');
        }

        if (format === '*l' || format === 'l') {
            let nlIdx = -1;
            for (let i = info.position; i < info.buffer.length; i++) {
                if (info.buffer[i] === 0x0A) { nlIdx = i; break; }
            }

            let line;
            if (nlIdx !== -1) {
                line = info.buffer.slice(info.position, nlIdx);
                if (line.length > 0 && line[line.length - 1] === 0x0D) line = line.slice(0, -1);
                info.position = nlIdx + 1;
            } else {
                line = info.buffer.slice(info.position);
                info.position = info.buffer.length;
            }

            if (!line.length) return null;
            return 'hex:' + line.toString('hex');
        }

        if (format === '*n' || format === 'n') {
            const rest = info.buffer.slice(info.position).toString('utf8');
            const match = rest.match(/^(-?\d+\.?\d*)/);
            
            if (!match) return null;
            
            info.position += match[0].length;
            
            return parseFloat(match[0]);
        }

        if (typeof format === 'number') {
            const chunk = info.buffer.slice(info.position, info.position + format);
            
            info.position += chunk.length;
            
            if (!chunk.length) return null;
            return 'hex:' + chunk.toString('hex');
        }

        return null;
    }

    write(handle, ...args) {
        if (!this.fileHandles.has(handle)) return false;

        const info = this.fileHandles.get(handle);
        const raw = args.join(' ');
        const data = raw.startsWith('hex:') ? Buffer.from(raw.slice(4), 'hex') : Buffer.from(raw, 'utf8');

        if (info.mode.includes('a')) {
            info.buffer = Buffer.concat([info.buffer, data]);
            info.position = info.buffer.length;
        } else {
            const before = info.buffer.slice(0, info.position);
            const after = info.buffer.slice(info.position + data.length);

            info.buffer = Buffer.concat([before, data, after]);
            info.position += data.length;
        }

        info.dirty = true;
        return true;
    }

    seek(handle, whence, offset) {
        if (!this.fileHandles.has(handle)) return null;
        const info = this.fileHandles.get(handle);
        
        offset = offset || 0;

        if (whence === 'set') {
            info.position = offset;
        } else if (whence === 'cur') {
            info.position += offset;
        } else if (whence === 'end') {
            info.position = info.buffer.length + offset;
        }

        info.position = Math.max(0, Math.min(info.position, info.buffer.length));
        return info.position;
    }

    input(handle) {
        if (handle === undefined) return this.currentInputHandle;
        if (this.fileHandles.has(handle)) { this.currentInputHandle = handle; return handle; }
        return null;
    }

    output(handle) {
        if (handle === undefined) return this.currentOutputHandle;
        if (this.fileHandles.has(handle)) { this.currentOutputHandle = handle; return handle; }
        return null;
    }

    lines(filename) {
        const raw = _readFileBuffer(_normalize(String(filename)));
        if (!raw) return [];
        return raw.toString('utf8')
            .split('\n')
            .map(l => l.replace(/\r$/, ''))
            .filter(l => l.length > 0);
    }

    tmpfile() {
        const tmpPath = path.join(os.tmpdir(), `sb_fix_tmp_${process.pid}_${Date.now()}`);
        return this.open(tmpPath, 'w+');
    }

    type(obj) {
        return this.fileHandles.has(obj) ? 'file' : null;
    }

    popen(command, mode) {
        let data = '';
        try {
            const result = spawnSync(command, [], { shell: true, encoding: 'utf8' });
            data = result.stdout || '';
        } catch (_) {}
        const handle = this.nextHandle++;
        this.processData.set(handle, { stdout: data });
        return handle;
    }
}

const _scanDir = function (dirPath) {
    try {
        const p = _normalize(String(dirPath));
        const result = IS_WIN ? _run(`dir /B ${_quote(p)}`, true) : _run(`find ${_quote(p)} -maxdepth 1 -mindepth 1`, true);
        if (!result.success) return [];

        return result.output
            .split('\n')
            .map(l => l.trim())
            .filter(Boolean)
            .map(f => path.basename(f));
    } catch (_) {
        return [];
    }
};

exports('ScanDir', _scanDir);

const luaIO = new LuaIO();

exports('GetIoLib', () => {
    return {
        open: (_, filename, mode) => {
            let handle = luaIO.open(filename, mode);
            return handle;
        },
        close: (handle) => {
            return luaIO.close(handle);
        },
        read: (handle, format, ...args) => {
            return luaIO.read(handle, format, ...args);
        },
        write: (handle, ...args) => {
            return luaIO.write(handle, ...args);
        },
        seek: (handle, whence, offset) => {
            return luaIO.seek(handle, whence, offset);
        },
        input: (handle) => {
            return luaIO.input(handle);
        },
        output: (handle) => {
            return luaIO.output(handle);
        },
        lines: (filename) => {
            return luaIO.lines(filename);
        },
        flush: (handle) => {
            return luaIO.flush(handle);
        },
        tmpfile: () => {
            return luaIO.tmpfile();
        },
        type: (obj) => {
            return luaIO.type(obj);
        },
        popen: (command, mode) => {
            return luaIO.popen(command, mode);
        }
    }
});

class LuaOS {
    execute(command) {
        return spawn(command, { shell: true, stdio: ['pipe', 'pipe', 'pipe'] });
    }

    getenv(varname) {
        return process.env[varname] || null;
    }

    remove(file) {
        const p = _normalize(String(file));
        return _run(IS_WIN ? `del /F /Q ${_quote(p)} 2>nul` : `rm -f ${_quote(p)}`, true);
    }

    rename(oldname, newname) {
        const op = _normalize(String(oldname));
        const np = _normalize(String(newname));
        return _run(IS_WIN ? `move /Y ${_quote(op)} ${_quote(np)}` : `mv -f ${_quote(op)} ${_quote(np)}`, true);
    }

    setlocale() { return null; }

    time() { return Math.floor(Date.now() / 1000); }

    tmpname() {
        return path.join(os.tmpdir(), `sb_fix_os_${process.pid}_${Date.now()}`);
    }
}

const luaOS = new LuaOS();

exports('GetOsLib', () => {
    return {
        execute: (command) => {
            return luaOS.execute(command);
        },
        getenv: (varname) => {
            return luaOS.getenv(varname);
        },
        remove: (file) => {
            luaOS.remove(file);
        },
        rename: (oldname, newname) => {
            luaOS.rename(oldname, newname);
        },
        setlocale: (locale) => {
            return luaOS.setlocale(locale);
        },
        time: () => {
            return luaOS.time();
        },
        tmpname: () => {
            return luaOS.tmpname();
        }
    }
});
