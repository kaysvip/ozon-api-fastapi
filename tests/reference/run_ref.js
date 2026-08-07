/*
 * 跑参考实现，把结果打到 stdout（JSON）。
 * Math.random 与 KDF salt 都被钉死，才能和 Python 侧逐字节比对。
 *
 * 用法: node run_ref.js <input.json>
 */
const fs = require('fs');
const path = require('path');
const CryptoJs = require('crypto-js');
const ref = require('./ozon_result.js');

const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

const page = ref.parse_page(input.html);
const pow = ref.solve_pow(input.html);

const out = {
    page: {
        challenge: page.challenge,
        scriptLine: page.scriptLine,
        cols: page.cols,
        template: page.template,
    },
    pow: {
        challenge: pow.challenge, version: pow.version, id: pow.id, token: pow.token,
        template: pow.template, scriptLine: pow.scriptLine, cols: pow.cols,
        pzs: pow.pzs, pzc: pow.pzc,
    },
    crc32: ref.crc32(input.user_agent + '3'),
    browser_2: ref.build_browser_2(input.template, input.user_agent, '3'),
    cases: [],
    bytecode: (input.bytecode_scripts || []).map(s => ref.readBrowser2Template(s)),
};

const realRandom = Math.random;
const realWaRandom = CryptoJs.lib.WordArray.random;
try {
    for (const c of input.cases) {
        Math.random = () => c.random_key;
        const salt = CryptoJs.enc.Hex.parse(c.salt_hex);
        CryptoJs.lib.WordArray.random = () => salt.clone();

        const params = ref.get_params(input.href, input.user_agent,
            Object.assign({}, c.dyn, { pow: pow }));
        out.cases.push({
            fp: params.fp,
            token: params.token,
            browser_2: params.browser_2,
            timings: params.timings,
        });
    }
} finally {
    Math.random = realRandom;
    CryptoJs.lib.WordArray.random = realWaRandom;
}

process.stdout.write(JSON.stringify(out));
