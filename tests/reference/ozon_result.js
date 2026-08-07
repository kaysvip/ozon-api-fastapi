const CryptoJs = require("crypto-js");

function md5(msg) {
    return CryptoJs.MD5(msg).toString();
}

function md5Word(str) {
    return new CryptoJs.algo.MD5.init().finalize(str);
}

function toBinary(A) {
    let t = [];
    for (let r = 0; r < A.sigBytes; r++) {
        const n = (A.words[r >>> 2] >>> 24 - r % 4 * 8 & 255).toString(2);
        t.push(Array(8 - n.length + 1).join("0") + n);
    }
    return t.join("");
}

// 工作量证明：找出使 md5(str + n) 的二进制前 dis 位全为 0 的最小 n
function hash(str, dis) {
    const target = Array(dis + 1).join('0');
    let cout = 0;
    while (!toBinary(md5Word(str + cout++)).startsWith(target)) { }
    return cout - 1;
}

function str2code(a) {
    const b = [];
    for (let i = 0; i < a.length; i++) b.push(a.charCodeAt(i));
    return b;
}

function get_count(arr) {
    let sum = 0;
    for (let i = 0; i < arr.length; i++) sum += arr[i];
    return sum;
}

function getConfig(challenge) {
    const challenge_data = atob(challenge.substring(3)).split(',');
    const random_key_md5 = md5(Math.random().toString());
    let key = md5(md5(random_key_md5.slice(0, 4)) + challenge_data[2]);
    const md5_num = get_count(str2code(challenge_data[1])) % 4;
    for (let i = 0; i < md5_num; i++) key = md5(key);
    return [{ key: key, keyLength: 8, ivLength: 4 }, challenge_data, random_key_md5];
}

function kdf_encrypt(text, kdfConfig) {
    const kdfResult = CryptoJs.kdf.OpenSSL.execute(kdfConfig.key, kdfConfig.keyLength, kdfConfig.ivLength);
    const encResult = CryptoJs.AES.encrypt(text.toString(), kdfResult.key, kdfResult);
    encResult.salt = kdfResult.salt;
    return CryptoJs.format.OpenSSL.stringify(encResult);
}

function kdf_decrypt(cipher, kdfConfig) {
    const parseResult = CryptoJs.format.OpenSSL.parse(cipher);
    const kdfResult = CryptoJs.kdf.OpenSSL.execute(
        kdfConfig.key, kdfConfig.keyLength, kdfConfig.ivLength, parseResult.salt);
    const decResult = CryptoJs.AES.decrypt(parseResult, kdfResult.key, {
        iv: kdfResult.iv, mode: CryptoJs.mode.CBC, padding: CryptoJs.pad.Pkcs7
    });
    return Array.from(Buffer.from(decResult.toString(), 'hex'));
}

/**
 * fp 静态底板：真实浏览器（Edge 151 / Windows）跑挑战页产出的原始数据，
 * 已经 /abt/result 校验通过。每次请求都会变的字段留 null，运行时填。
 */
const FP_BASE = {
    "challenge": null,
    "user_agent": null,
    "browser": {
        "isFirefox": false,
        "isChrome": true,
        "isSafari": false,
        "isOpera": false,
        "isIE": false,
        "isEdge": false,
        "isEdgeChromium": true,
        "isBlink": true
    },
    "props": "838|839|1194|297|1053|-1|844|902|1228|155|347|737|82|414|75",
    "screen_1": {
        "@proto:Screen": {
            "@proto:EventTarget": {},
            "@get:isExtended": false,
            "@get:onchange": "_n_",
            "@get:orientation": {
                "@proto:ScreenOrientation": {
                    "@proto:EventTarget": "_m_",
                    "@get:onchange": "_n_",
                    "@get:type": "landscape-primary",
                    "@get:angle": 0
                }
            },
            "@get:availTop": 0,
            "@get:availLeft": 0,
            "@get:pixelDepth": 24,
            "@get:colorDepth": 24,
            "@get:height": 914,
            "@get:width": 1912,
            "@get:availHeight": 914,
            "@get:availWidth": 1912
        }
    },
    "screen_2": {
        "tiWidth": 1912,
        "tiHeight": 914,
        "toWidth": 1928,
        "toHeight": 1002,
        "dbcr": {
            "x": 0,
            "y": 0,
            "width": 1912,
            "height": 914,
            "top": 0,
            "right": 1912,
            "bottom": 914,
            "left": 0
        },
        "sx": 10,
        "sy": 10,
        "sch": 914,
        "scw": 1912
    },
    "screen_3": {
        "@val:dwh": false,
        "@val:dwvs": "visible",
        "@val:dfe": true,
        "@val:dwfe": true,
        "@val:wv": {
            "@proto:VisualViewport": {
                "@proto:EventTarget": {},
                "@get:onscrollend": "_n_",
                "@get:onscroll": "_n_",
                "@get:onresize": "_n_",
                "@get:scale": 1,
                "@get:height": 914,
                "@get:width": 1912,
                "@get:pageTop": 0,
                "@get:pageLeft": 0,
                "@get:offsetTop": 0,
                "@get:offsetLeft": 0
            }
        }
    },
    "touch": false,
    "battery": {
        "@proto:BatteryManager": {
            "@get:level": 1,
            "@get:dischargingTime": null,
            "@get:chargingTime": 0,
            "@get:charging": true
        }
    },
    "location": null,
    "context": {
        "@val:gcrw": false,
        "@val:wk": false,
        "@val:n": "_u_",
        "@val:ph": "_u_",
        "@val:cph": "_u_",
        "@val:opera": "_u_",
        "@val:opr": "_u_",
        "@val:chrome": {
            "@val:app": {
                "@val:RunningState": "_m_",
                "@val:InstallState": "_m_",
                "@val:runningState": "_fn_",
                "@val:installState": "_fn_",
                "@val:getIsInstalled": "_fn_",
                "@val:getDetails": "_fn_",
                "@val:isInstalled": false
            },
            "@val:csi": "_fn_",
            "@val:loadTimes": "_fn_"
        },
        "@val:w": false,
        "@val:wsc": true
    },
    "storage": {
        "quota": 6442450944,
        "usage": 0,
        "usageDetails": {}
    },
    "hev": {
        "architecture": "x86",
        "bitness": "64",
        "brands": [
            {
                "brand": "Not=A?Brand",
                "version": "99"
            },
            {
                "brand": "Microsoft Edge",
                "version": "151"
            },
            {
                "brand": "Chromium",
                "version": "151"
            }
        ],
        "formFactors": [
            "Desktop"
        ],
        "fullVersionList": [
            {
                "brand": "Not=A?Brand",
                "version": "99.0.0.0"
            },
            {
                "brand": "Microsoft Edge",
                "version": "151.0.4129.59"
            },
            {
                "brand": "Chromium",
                "version": "151.0.7922.72"
            }
        ],
        "mobile": false,
        "model": "",
        "platform": "Windows",
        "platformVersion": "19.0.0",
        "uaFullVersion": "151.0.4129.59",
        "wow64": false
    },
    "media_devices": {
        "md": [
            {
                "kind": "audioinput",
                "label": "",
                "deviceId": "",
                "groupId": ""
            },
            {
                "kind": "audiooutput",
                "label": "",
                "deviceId": "",
                "groupId": ""
            }
        ],
        "edn": "enumerateDevices",
        "ed": "function enumerateDevices() { [native code] }"
    },
    "navigator": {
        "@proto:Navigator": {
            "@val:unregisterProtocolHandler": "_fn_",
            "@val:registerProtocolHandler": "_fn_",
            "@val:getInterestGroupAdAuctionData": "_fn_",
            "@val:getInstalledRelatedApps": "_fn_",
            "@val:deprecatedURNToURL": "_fn_",
            "@val:deprecatedReplaceInURN": "_fn_",
            "@val:updateAdInterestGroups": "_fn_",
            "@val:leaveAdInterestGroup": "_fn_",
            "@val:joinAdInterestGroup": "_fn_",
            "@val:createAuctionNonce": "_fn_",
            "@val:clearOriginJoinedAdInterestGroups": "_fn_",
            "@val:webkitGetUserMedia": "_fn_",
            "@val:setAppBadge": "_fn_",
            "@val:requestMediaKeySystemAccess": "_fn_",
            "@val:requestMIDIAccess": "_fn_",
            "@val:getUserMedia": "_fn_",
            "@val:getBattery": "_fn_",
            "@val:clearAppBadge": "_fn_",
            "@val:share": "_fn_",
            "@val:canShare": "_fn_",
            "@val:canLoadAdAuctionFencedFrame": "_fn_",
            "@val:runAdAuction": "_fn_",
            "@val:adAuctionComponents": "_fn_",
            "@get:storageBuckets": {
                "@proto:StorageBucketManager": {
                    "@val:constructor": "_fn_",
                    "@val:open": "_fn_",
                    "@val:keys": "_fn_",
                    "@val:delete": "_fn_"
                }
            },
            "@get:xr": {
                "@proto:XRSystem": {
                    "@proto:EventTarget": {
                        "@val:constructor": "_fn_",
                        "@val:when": "_fn_",
                        "@val:removeEventListener": "_fn_",
                        "@val:dispatchEvent": "_fn_",
                        "@val:addEventListener": "_fn_"
                    },
                    "@val:constructor": "_fn_",
                    "@val:requestSession": "_fn_",
                    "@val:isSessionSupported": "_fn_",
                    "@get:ondevicechange": "_n_"
                }
            },
            "@get:usb": {
                "@proto:USB": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:requestDevice": "_fn_",
                    "@val:constructor": "_fn_",
                    "@val:getDevices": "_fn_",
                    "@get:ondisconnect": "_n_",
                    "@get:onconnect": "_n_"
                }
            },
            "@get:serial": {
                "@proto:Serial": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:requestPort": "_fn_",
                    "@val:constructor": "_fn_",
                    "@val:getPorts": "_fn_",
                    "@get:ondisconnect": "_n_",
                    "@get:onconnect": "_n_"
                }
            },
            "@get:presentation": {
                "@proto:Presentation": {
                    "@val:constructor": "_fn_",
                    "@get:receiver": "_n_",
                    "@get:defaultRequest": "_n_"
                }
            },
            "@get:mediaSession": {
                "@proto:MediaSession": {
                    "@val:constructor": "_fn_",
                    "@val:setPositionState": "_fn_",
                    "@val:setMicrophoneActive": "_fn_",
                    "@val:setCameraActive": "_fn_",
                    "@val:setActionHandler": "_fn_",
                    "@get:playbackState": "none",
                    "@get:metadata": "_n_"
                }
            },
            "@get:hid": {
                "@proto:HID": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:requestDevice": "_fn_",
                    "@val:constructor": "_fn_",
                    "@val:getDevices": "_fn_",
                    "@get:ondisconnect": "_n_",
                    "@get:onconnect": "_n_"
                }
            },
            "@get:devicePosture": {
                "@proto:DevicePosture": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:constructor": "_fn_",
                    "@get:onchange": "_n_",
                    "@get:type": "continuous"
                }
            },
            "@get:permissions": {
                "@proto:Permissions": {
                    "@val:constructor": "_fn_",
                    "@val:query": "_fn_"
                }
            },
            "@get:mediaCapabilities": {
                "@proto:MediaCapabilities": {
                    "@val:constructor": "_fn_",
                    "@val:encodingInfo": "_fn_",
                    "@val:decodingInfo": "_fn_"
                }
            },
            "@get:ink": {
                "@proto:Ink": {
                    "@val:constructor": "_fn_",
                    "@val:requestPresenter": "_fn_"
                }
            },
            "@get:login": {
                "@proto:NavigatorLogin": {
                    "@val:constructor": "_fn_",
                    "@val:setStatus": "_fn_"
                }
            },
            "@get:gpu": {
                "@proto:GPU": {
                    "@val:constructor": "_fn_",
                    "@val:requestAdapter": "_fn_",
                    "@val:getPreferredCanvasFormat": "_fn_",
                    "@get:wgslLanguageFeatures": {
                        "@proto:WGSLLanguageFeatures": "_m_"
                    }
                }
            },
            "@get:storage": {
                "@proto:StorageManager": {
                    "@val:persist": "_fn_",
                    "@val:getDirectory": "_fn_",
                    "@val:constructor": "_fn_",
                    "@val:persisted": "_fn_",
                    "@val:estimate": "_fn_"
                }
            },
            "@get:locks": {
                "@proto:LockManager": {
                    "@val:constructor": "_fn_",
                    "@val:request": "_fn_",
                    "@val:query": "_fn_"
                }
            },
            "@get:userAgentData": {
                "@proto:NavigatorUAData": {
                    "@val:constructor": "_fn_",
                    "@val:toJSON": "_fn_",
                    "@val:getHighEntropyValues": "_fn_",
                    "@get:platform": "Windows",
                    "@get:mobile": false,
                    "@get:brands": {
                        "@arr:length": 3,
                        "@arr:2": "_m_",
                        "@arr:1": "_m_",
                        "@arr:0": "_m_"
                    }
                }
            },
            "@get:deviceMemory": 32,
            "@get:wakeLock": {
                "@proto:WakeLock": {
                    "@val:constructor": "_fn_",
                    "@val:request": "_fn_"
                }
            },
            "@get:virtualKeyboard": {
                "@proto:VirtualKeyboard": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:constructor": "_fn_",
                    "@val:show": "_fn_",
                    "@val:hide": "_fn_",
                    "@get:ongeometrychange": "_n_",
                    "@get:overlaysContent": false,
                    "@get:boundingRect": {
                        "@proto:DOMRect": "_m_"
                    }
                }
            },
            "@get:serviceWorker": {
                "@proto:ServiceWorkerContainer": {
                    "@getter:ready": "function get ready() { [native code] }",
                    "@proto:EventTarget": "@ref:7",
                    "@val:constructor": "_fn_",
                    "@val:startMessages": "_fn_",
                    "@val:register": "_fn_",
                    "@val:getRegistrations": "_fn_",
                    "@val:getRegistration": "_fn_",
                    "@get:onmessageerror": "_n_",
                    "@get:onmessage": "_n_",
                    "@get:oncontrollerchange": "_n_",
                    "@get:ready": {
                        "@proto:Promise": "_m_"
                    },
                    "@get:controller": "_n_"
                }
            },
            "@get:mediaDevices": {
                "@proto:MediaDevices": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:constructor": "_fn_",
                    "@val:setCaptureHandleConfig": "_fn_",
                    "@val:getDisplayMedia": "_fn_",
                    "@val:getUserMedia": "_fn_",
                    "@val:getSupportedConstraints": "_fn_",
                    "@val:enumerateDevices": "_fn_",
                    "@get:ondevicechange": "_n_"
                }
            },
            "@get:managed": {
                "@proto:NavigatorManagedData": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:constructor": "_fn_",
                    "@val:getManagedConfiguration": "_fn_",
                    "@get:onmanagedconfigurationchange": "_n_"
                }
            },
            "@get:keyboard": {
                "@proto:Keyboard": {
                    "@val:constructor": "_fn_",
                    "@val:unlock": "_fn_",
                    "@val:lock": "_fn_",
                    "@val:getLayoutMap": "_fn_"
                }
            },
            "@get:credentials": {
                "@proto:CredentialsContainer": {
                    "@val:constructor": "_fn_",
                    "@val:store": "_fn_",
                    "@val:preventSilentAccess": "_fn_",
                    "@val:get": "_fn_",
                    "@val:create": "_fn_"
                }
            },
            "@get:clipboard": {
                "@proto:Clipboard": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:constructor": "_fn_",
                    "@val:writeText": "_fn_",
                    "@val:write": "_fn_",
                    "@val:readText": "_fn_",
                    "@val:read": "_fn_",
                    "@get:onclipboardchange": "_n_"
                }
            },
            "@get:bluetooth": {
                "@proto:Bluetooth": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:constructor": "_fn_",
                    "@val:requestDevice": "_fn_",
                    "@val:getAvailability": "_fn_"
                }
            },
            "@get:protectedAudience": {
                "@proto:ProtectedAudience": {
                    "@val:constructor": "_fn_",
                    "@val:queryFeatureSupport": "_fn_"
                }
            },
            "@get:deprecatedRunAdAuctionEnforcesKAnonymity": false,
            "@val:constructor": "_fn_",
            "@val:vibrate": "_fn_",
            "@val:sendBeacon": "_fn_",
            "@val:javaEnabled": "_fn_",
            "@val:getGamepads": "_fn_",
            "@get:connection": {
                "@proto:NetworkInformation": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:constructor": "_fn_",
                    "@get:saveData": false,
                    "@get:downlink": null,
                    "@get:rtt": null,
                    "@get:effectiveType": null,
                    "@get:onchange": "_n_"
                }
            },
            "@get:pdfViewerEnabled": true,
            "@get:mimeTypes": {
                "@proto:MimeTypeArray": {
                    "@val:constructor": "_fn_",
                    "@val:namedItem": "_fn_",
                    "@val:item": "_fn_",
                    "@get:length": 2
                },
                "@val:text/pdf": {
                    "@proto:MimeType": {
                        "@val:constructor": "_fn_",
                        "@get:enabledPlugin": "_m_",
                        "@get:description": "Portable Document Format",
                        "@get:suffixes": "pdf",
                        "@get:type": "text/pdf"
                    }
                },
                "@val:application/pdf": {
                    "@proto:MimeType": "@ref:65"
                },
                "@val:1": "@ref:64",
                "@val:0": "@ref:66"
            },
            "@get:plugins": {
                "@proto:PluginArray": {
                    "@val:constructor": "_fn_",
                    "@val:refresh": "_fn_",
                    "@val:namedItem": "_fn_",
                    "@val:item": "_fn_",
                    "@get:length": 5
                },
                "@val:WebKit built-in PDF": {
                    "@proto:Plugin": {
                        "@val:constructor": "_fn_",
                        "@val:namedItem": "_fn_",
                        "@val:item": "_fn_",
                        "@get:length": 2,
                        "@get:description": "Portable Document Format",
                        "@get:filename": "internal-pdf-viewer",
                        "@get:name": "WebKit built-in PDF"
                    },
                    "@val:text/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:application/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:1": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:0": {
                        "@proto:MimeType": "_m_"
                    }
                },
                "@val:Microsoft Edge PDF Viewer": {
                    "@proto:Plugin": "@ref:70",
                    "@val:text/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:application/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:1": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:0": {
                        "@proto:MimeType": "_m_"
                    }
                },
                "@val:Chromium PDF Viewer": {
                    "@proto:Plugin": "@ref:70",
                    "@val:text/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:application/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:1": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:0": {
                        "@proto:MimeType": "_m_"
                    }
                },
                "@val:Chrome PDF Viewer": {
                    "@proto:Plugin": "@ref:70",
                    "@val:text/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:application/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:1": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:0": {
                        "@proto:MimeType": "_m_"
                    }
                },
                "@val:PDF Viewer": {
                    "@proto:Plugin": "@ref:70",
                    "@val:text/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:application/pdf": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:1": {
                        "@proto:MimeType": "_m_"
                    },
                    "@val:0": {
                        "@proto:MimeType": "_m_"
                    }
                },
                "@val:4": "@ref:69",
                "@val:3": "@ref:75",
                "@val:2": "@ref:80",
                "@val:1": "@ref:85",
                "@val:0": "@ref:90"
            },
            "@get:webdriver": false,
            "@get:onLine": true,
            "@get:languages": {
                "@arr:length": 4,
                "@arr:3": "en-US",
                "@arr:2": "en-GB",
                "@arr:1": "en",
                "@arr:0": "zh-CN"
            },
            "@get:language": "zh-CN",
            "@get:userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0",
            "@get:product": "Gecko",
            "@get:platform": "Win32",
            "@get:appVersion": "5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36 Edg/151.0.0.0",
            "@get:appName": "Netscape",
            "@get:appCodeName": "Mozilla",
            "@get:cookieEnabled": true,
            "@get:hardwareConcurrency": 24,
            "@get:windowControlsOverlay": {
                "@proto:WindowControlsOverlay": {
                    "@proto:EventTarget": "@ref:7",
                    "@val:constructor": "_fn_",
                    "@val:getTitlebarAreaRect": "_fn_",
                    "@get:ongeometrychange": "_n_",
                    "@get:visible": false
                }
            },
            "@get:webkitPersistentStorage": {
                "@proto:Object": {
                    "@val:requestQuota": "_fn_",
                    "@val:queryUsageAndQuota": "_fn_"
                }
            },
            "@get:webkitTemporaryStorage": "@ref:98",
            "@get:doNotTrack": "_n_",
            "@get:geolocation": {
                "@proto:Geolocation": {
                    "@val:constructor": "_fn_",
                    "@val:watchPosition": "_fn_",
                    "@val:getCurrentPosition": "_fn_",
                    "@val:clearWatch": "_fn_"
                }
            },
            "@get:userActivation": {
                "@proto:UserActivation": {
                    "@val:constructor": "_fn_",
                    "@get:isActive": false,
                    "@get:hasBeenActive": true
                }
            },
            "@get:scheduling": {
                "@proto:Scheduling": {
                    "@val:constructor": "_fn_",
                    "@val:isInputPending": "_fn_"
                }
            },
            "@get:maxTouchPoints": 10,
            "@get:vendor": "Google Inc.",
            "@get:productSub": "20030107",
            "@get:vendorSub": ""
        }
    },
    "performance": null,
    "video": {
        "audio/aac": "probably",
        "audio/x-m4a": "maybe",
        "video/mp4; codecs=\"avc1.42E01E\"": "probably"
    },
    "webgl": {
        "ext": "ANGLE_instanced_arrays;EXT_blend_minmax;EXT_clip_control;EXT_color_buffer_half_float;EXT_depth_clamp;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_polygon_offset_clamp;EXT_sRGB;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_texture_mirror_clamp_to_edge;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_blend_func_extended;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw;WEBGL_polygon_mode",
        "ext_vec": "ANGLE_instanced_arrays;EXT_blend_minmax;EXT_clip_control;EXT_color_buffer_half_float;EXT_depth_clamp;EXT_disjoint_timer_query;EXT_float_blend;EXT_frag_depth;EXT_polygon_offset_clamp;EXT_sRGB;EXT_shader_texture_lod;EXT_texture_compression_bptc;EXT_texture_compression_rgtc;EXT_texture_filter_anisotropic;EXT_texture_mirror_clamp_to_edge;KHR_parallel_shader_compile;OES_element_index_uint;OES_fbo_render_mipmap;OES_standard_derivatives;OES_texture_float;OES_texture_float_linear;OES_texture_half_float;OES_texture_half_float_linear;OES_vertex_array_object;WEBGL_blend_func_extended;WEBGL_color_buffer_float;WEBGL_compressed_texture_s3tc;WEBGL_compressed_texture_s3tc_srgb;WEBGL_debug_renderer_info;WEBGL_debug_shaders;WEBGL_depth_texture;WEBGL_draw_buffers;WEBGL_lose_context;WEBGL_multi_draw;WEBGL_polygon_mode",
        "renderer": "WebKit WebGL",
        "version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
        "gp": "function getParameter() { [native code] }",
        "gse": "function getSupportedExtensions() { [native code] }",
        "x": {
            "@proto:WebGLRenderingContext": {
                "@get:canvas": {
                    "@proto:HTMLCanvasElement": "_m_"
                }
            }
        },
        "hash": "f3bd24f5b153d57f5817372fd5f22573",
        "unmasked_vendor": "Google Inc. (NVIDIA)",
        "unmasked_renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Ti SUPER (0x00002705) Direct3D11 vs_5_0 ps_5_0, D3D11)"
    },
    "canvas": {
        "hash": "f875c525afac4307380cc6366061bb10"
    },
    "fn_1": null,
    "fn_2": {
        "f": "111111111111111"
    },
    "fn_3": {
        "@f": "function Function() { [native code] }",
        "@proto:Function": {
            "@f": "function () { [native code] }",
            "@get:arguments": "TypeError: 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode functions or the arguments objects for calls to them",
            "@get:caller": "TypeError: 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode functions or the arguments objects for calls to them",
            "@val:toString": {
                "@f": "function toString() { [native code] }",
                "@proto:Function": "@ref:2",
                "@val:name": "toString",
                "@val:length": 0
            },
            "@val:call": {
                "@f": "function call() { [native code] }",
                "@proto:Function": "@ref:2",
                "@val:name": "call",
                "@val:length": 1
            },
            "@val:bind": {
                "@f": "function bind() { [native code] }",
                "@proto:Function": "@ref:2",
                "@val:name": "bind",
                "@val:length": 1
            },
            "@val:apply": {
                "@f": "function apply() { [native code] }",
                "@proto:Function": "@ref:2",
                "@val:name": "apply",
                "@val:length": 2
            },
            "@val:constructor": "@ref:1",
            "@val:name": "",
            "@val:length": 0
        },
        "@val:prototype": "@ref:2",
        "@val:name": "Function",
        "@val:length": 1
    },
    "ts": null,
    "nonce": null,
    "pzs": null,
    "pzc": null,
    "css": {
        "color-gamut": [
            "srgb"
        ],
        "min-resolution": [
            "96dpi"
        ],
        "prefers-contrast": [
            "no-preference"
        ],
        "dynamic-range": [
            "standard"
        ],
        "video-dynamic-range": [],
        "any-hover": [
            "hover"
        ],
        "any-pointer": [
            "coarse"
        ],
        "pointer": [
            "fine"
        ],
        "hover": [
            "hover"
        ],
        "update": [
            "fast"
        ],
        "overflow-block": [
            "scroll"
        ],
        "overflow-inline": [
            "scroll"
        ],
        "inverted-colors": [],
        "prefers-reduced-motion": [
            "no-preference"
        ],
        "prefers-reduced-transparency": [
            "no-preference"
        ],
        "scripting": [
            "enabled"
        ],
        "forced-colors": [
            "none"
        ],
        "prefers-color-scheme": [
            "light"
        ],
        "orientation": [
            "landscape"
        ],
        "scan": [],
        "max-monochrome": [
            "0"
        ],
        "-webkit-min-device-pixel-ratio": [
            "1"
        ]
    },
    "rtc": {
        "video": [
            "video/VP8:90000::",
            "video/rtx:90000::",
            "video/H264:90000::level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f",
            "video/H264:90000::level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f",
            "video/H264:90000::level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
            "video/H264:90000::level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f",
            "video/H264:90000::level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d001f",
            "video/H264:90000::level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=4d001f",
            "video/AV1:90000::level-idx=5;profile=0;tier=0",
            "video/VP9:90000::profile-id=0",
            "video/VP9:90000::profile-id=2",
            "video/H264:90000::level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032",
            "video/red:90000::",
            "video/ulpfec:90000::"
        ],
        "audio": [
            "audio/opus:48000:2:minptime=10;useinbandfec=1",
            "audio/red:48000:2:",
            "audio/G722:8000:1:",
            "audio/PCMU:8000:1:",
            "audio/PCMA:8000:1:",
            "audio/CN:8000:1:",
            "audio/telephone-event:48000:1:",
            "audio/telephone-event:8000:1:"
        ]
    },
    "fonts": "00000001100100000111000011110011010010000011010100011111100011111111000111111",
    "browser_2": null,
    "timings": null,
    "ctm": null
};

// 字段顺序会进 JSON.stringify，必须和浏览器一致
const FP_KEY_ORDER = ["challenge","user_agent","browser","props","screen_1","screen_2","screen_3","touch","battery","location","context","storage","hev","media_devices","navigator","performance","video","webgl","canvas","fn_1","fn_2","fn_3","ts","nonce","pzs","pzc","css","rtc","fonts","browser_2","timings","ctm"];

/* ------------------------------------------------------------------ *
 *  页面解析：challenge、混淆脚本位置、browser_2 模板
 * ------------------------------------------------------------------ */

// fn_1 调用栈里的 5 个栈帧。脚本每次重新混淆，b[0x..] 的下标会变，
// 所以把十六进制下标通配掉，靠代码形状定位。
const FRAME_PATTERNS = [
    /try\{return window\[b\[0x[\da-f]+\]\]\[b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\[b\[0x[\da-f]+\]\]\}catch/,
    /e,f,l;g\(e=a\[b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\(\),f=a\[b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\(\)/,
    /var f;g\(this\[b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\[b\[0x[\da-f]+\]\]\(\[this\[/,
    /0x[\da-f]+\]\+b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\+b\[0x[\da-f]+\]\]\(\),a\[b\[0x[\da-f]+\]\]\(d,function\(\)/,
    /\]\(\)\(\);if\(q!==void b\[0x[\da-f]+\]\)\{p=\[\]\[b\[0x[\da-f]+\]\]\(bA\(p\),bA\(q\)\)/
];

// 页面脚本里最长的那个 base64 字面量就是虚拟机字节码
function extractBytecode(script) {
    const lits = script.match(/"[A-Za-z0-9+/=]{800,}"/g) || [];
    if (!lits.length) return null;
    const b64 = lits.map(x => x.slice(1, -1)).sort((a, b) => b.length - a.length)[0];
    // 对应虚拟机的 _decodeBytecode：atob 之后再把 >255 的码位拆成两字节
    const s = Buffer.from(b64, 'base64').toString('latin1');
    const out = [];
    for (let i = 0; i < s.length; i++) {
        let c = s.charCodeAt(i);
        if (c > 255) { out.push(c & 255); c >>= 8; }
        out.push(c);
    }
    return out;
}

// 字节码指令里的操作数宽度，用来在指令流里正确前进
const OPERAND_WIDTH = {
    2: 2, 3: 9, 4: 5, 10: 3, 11: -1, 12: 2, 14: -1, 15: 2, 16: 0,
    17: 5, 18: 4, 19: 5, 20: -1, 21: 3, 22: 9, 23: 1,
    50: 3, 51: 3, 52: 3, 53: 3, 54: 3, 55: 3, 56: 3, 57: 3,
    100: 3, 101: 3, 102: 3, 103: 3
};

/**
 * 解析出 browser_2 的模板串，形如 "ChromiumEdge************312"。
 * 它是主流程里的第一条 LOADSTR，'*' 之前是浏览器名，之后的数字是取 CRC32 字节的下标。
 * 这里按指令流逐条前进，而不是扫可打印字符，避免误命中。
 */
function readBrowser2Template(script) {
    const bc = extractBytecode(script);
    if (!bc) return null;
    let pc = 0;
    const byte = () => bc[pc++];
    const readStr = () => {
        // 虚拟机原样写法是 getByte()<<8 || getByte()，短路语义要照抄
        const n = (byte() << 8) || byte();
        let s = '';
        for (let i = 0; i < n; i++) s += String.fromCharCode(byte());
        return s;
    };
    while (pc < bc.length && pc < 4096) {
        const op = byte();
        if (op === 1) {                       // LOADSTR
            byte();                           // 目标寄存器
            const s = readStr();
            if (s.indexOf('*') !== -1) return s;
            continue;
        }
        if (op === 13) { pc += 5; pc += 1 + bc[pc]; continue; }   // FRAME
        if (op === 5) { byte(); pc += 1 + bc[pc]; continue; }     // LOADARR
        const w = OPERAND_WIDTH[op];
        if (w === undefined) return null;     // 指令表变了，交给上层报错
        if (w >= 0) { pc += w; continue; }
        if (op === 11) { pc += 3; pc += 1 + bc[pc]; continue; }   // CALL
        if (op === 14) { byte(); pc += 1 + bc[pc]; continue; }    // RET
        if (op === 20) { pc += 5; pc += 1 + bc[pc]; continue; }   // MKFUNC
    }
    return null;
}

/**
 * 从下发的挑战页里取出后续都要用到的东西
 * @param {string} html 挑战页 HTML
 */
function parse_page(html) {
    const challenge = (/id="challenge" type="hidden" value="(.*?)"/.exec(html) || [])[1];
    const lines = html.split('\n');
    let line = -1, script = '';
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].indexOf('<script>(function()') !== -1) { line = i + 1; script = lines[i]; break; }
    }
    const cols = FRAME_PATTERNS.map(re => {
        const m = re.exec(script);
        return m ? m.index + 1 : -1;      // V8 的列号从 1 开始
    });
    return {
        challenge: challenge || null,
        scriptLine: line,
        cols: cols,
        template: readBrowser2Template(script)
    };
}

/* ------------------------------------------------------------------ *
 *  browser_2
 * ------------------------------------------------------------------ */

let CRC_TABLE = null;

function crc32(str) {
    if (!CRC_TABLE) {
        CRC_TABLE = [];
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
            CRC_TABLE[i] = c >>> 0;
        }
    }
    let c = 0 ^ -1;
    for (let i = 0; i < str.length; i++) c = (c >>> 8) ^ CRC_TABLE[(c ^ str.charCodeAt(i)) & 255];
    return (c ^ -1) >>> 0;
}

/**
 * browser_2 = 浏览器名 + " v" + CRC32(user_agent + challenge版本号) 的三个指定字节
 * 名字和字节下标都写在页面字节码的模板串里，服务端会逐字符校验。
 */
function build_browser_2(template, user_agent, challenge_version) {
    const parts = String(template).split('*').filter(Boolean);
    const idx = (parts[1] || '012').split('');
    const d = crc32(user_agent + challenge_version);
    const bytes = [d >>> 24 & 255, d >>> 16 & 255, d >>> 8 & 255, d & 255];
    return parts[0] + ' v' + bytes[idx[0]] + '.' + bytes[idx[1]] + '.' + bytes[idx[2]];
}

/* ------------------------------------------------------------------ *
 *  对外接口
 *
 *  所有会变的值都由调用方（Python）生成后传进来，这里只组装和加密。
 *  唯一在 JS 侧产生的数字是工作量证明的实测耗时 —— PoW 只能在这里跑。
 * ------------------------------------------------------------------ */

/**
 * 解析挑战页并完成工作量证明。
 * 单独跑这一步，调用方才能拿到真实的 PoW 耗时去生成自洽的时间线。
 *
 * @param {string} html 挑战页 HTML
 */
function solve_pow(html) {
    const page = parse_page(html);
    if (!page.challenge) throw new Error('挑战页里没有 challenge');
    if (!page.template) throw new Error('页面字节码里没找到 browser_2 模板');

    const challenge_data = atob(page.challenge.substring(3)).split(',');
    const token = challenge_data[2];
    const dis = parseInt(JSON.parse(atob(token.split(':')[3])).pz);

    const pzs = token.slice(0, 20);
    const begin = Date.now();
    const pzc = hash(pzs, dis);

    return {
        challenge: page.challenge,
        version: challenge_data[0],
        id: challenge_data[1],
        token: token,
        template: page.template,
        scriptLine: page.scriptLine,
        cols: page.cols,
        pzs: pzs,
        pzc: pzc,
        pow_ms: Date.now() - begin
    };
}

/**
 * performance 对象。结构照搬真实抓包：挑战页是客户端跳转过来的，
 * 所以没有重定向记录；连接复用，DNS/TCP 各阶段与 fetchStart 重合。
 */
function buildPerformance(timeline, memory) {
    const t = timeline.timing;
    return {
        "@proto:Performance": {
            "@proto:EventTarget": {},
            "@get:interactionCount": 0,
            "@get:eventCounts": { "@proto:EventCounts": { "@get:size": 36 } },
            "@get:memory": {
                "@proto:Object": {
                    "@get:jsHeapSizeLimit": memory.limit,
                    "@get:usedJSHeapSize": memory.used,
                    "@get:totalJSHeapSize": memory.total
                }
            },
            "@get:navigation": {
                "@proto:PerformanceNavigation": {
                    "@val:TYPE_RESERVED": 255, "@val:TYPE_BACK_FORWARD": 2,
                    "@val:TYPE_RELOAD": 1, "@val:TYPE_NAVIGATE": 0,
                    "@get:redirectCount": 0, "@get:type": 0
                }
            },
            "@get:timing": {
                "@proto:PerformanceTiming": {
                    "@get:loadEventEnd": t.loadEventEnd,
                    "@get:loadEventStart": t.loadEventStart,
                    "@get:domComplete": t.domComplete,
                    "@get:domContentLoadedEventEnd": t.domContentLoadedEventEnd,
                    "@get:domContentLoadedEventStart": t.domContentLoadedEventStart,
                    "@get:domInteractive": t.domInteractive,
                    "@get:domLoading": t.domLoading,
                    "@get:responseEnd": t.responseEnd,
                    "@get:responseStart": t.responseStart,
                    "@get:requestStart": t.requestStart,
                    "@get:secureConnectionStart": t.secureConnectionStart,
                    "@get:connectEnd": t.connectEnd,
                    "@get:connectStart": t.connectStart,
                    "@get:domainLookupEnd": t.domainLookupEnd,
                    "@get:domainLookupStart": t.domainLookupStart,
                    "@get:fetchStart": t.fetchStart,
                    "@get:redirectEnd": t.redirectEnd,
                    "@get:redirectStart": t.redirectStart,
                    "@get:unloadEventEnd": t.unloadEventEnd,
                    "@get:unloadEventStart": t.unloadEventStart,
                    "@get:navigationStart": t.navigationStart
                }
            },
            "@get:onresourcetimingbufferfull": "_n_",
            "@get:timeOrigin": timeline.timeOrigin
        }
    };
}

function buildStack(href, line, cols) {
    const at = i => "(" + href + ":" + line + ":" + cols[i] + ")";
    return "TypeError: Function.prototype.toString requires that 'this' be a Function\n" +
        "    at Object.toString (<anonymous>)\n" +
        "    at Object.aQ [as fnCall1] " + at(0) + "\n" +
        "    at S.g.<computed>.<computed> " + at(1) + "\n" +
        "    at S.runFuncAt " + at(2) + "\n" +
        "    at " + href + ":" + line + ":" + cols[3] + "\n" +
        "    at async bE " + at(4);
}

/**
 * 组装并加密 fp
 *
 * @param {string} href       挑战页最终 URL
 * @param {string} user_agent 必须和请求头 user-agent 一字不差
 * @param {object} dyn        调用方生成的全部动态值：
 *        pow        solve_pow 的返回值
 *        ts         采集中途取的 Date.now()
 *        timings    28 项采集耗时，键序即采集顺序
 *        ctm        采集总耗时
 *        timeline   {timeOrigin, jobStart, jobEnd, timing:{...21 项}}
 *        connection {rtt, downlink, effectiveType}
 *        memory     {limit, used, total}
 */
function get_params(href, user_agent, dyn) {
    const pow = dyn.pow;
    const cfg = getConfig(pow.challenge);
    const kdfConfig = cfg[0], random_key_md5 = cfg[2];
    const origin = href.replace(/^(\w+:\/\/[^/?#]+).*$/, '$1');
    const browser_2 = build_browser_2(pow.template, user_agent, pow.version);
    const t = dyn.timeline.timing;

    const fp = JSON.parse(JSON.stringify(FP_BASE));
    fp.challenge = { id: pow.id, version: pow.version, checkStr: random_key_md5.slice(0, 10) };
    fp.user_agent = user_agent;
    fp.location = { "@val:referrer": href, "@val:ploc": origin, "@val:loc": origin };
    fp.performance = buildPerformance(dyn.timeline, dyn.memory);
    fp.fn_1 = {
        exc: "TypeError: Function.prototype.toString requires that 'this' be a Function",
        stack: buildStack(href, pow.scriptLine, pow.cols)
    };
    fp.ts = dyn.ts;
    fp.nonce = md5(String(dyn.ts)).slice(-7);
    fp.pzs = pow.pzs;
    fp.pzc = pow.pzc;
    fp.browser_2 = browser_2;
    fp.timings = dyn.timings;
    fp.ctm = dyn.ctm;

    const conn = fp.navigator["@proto:Navigator"]["@get:connection"]["@proto:NetworkInformation"];
    conn["@get:downlink"] = dyn.connection.downlink;
    conn["@get:rtt"] = dyn.connection.rtt;
    conn["@get:effectiveType"] = dyn.connection.effectiveType;

    const ordered = {};
    for (const k of FP_KEY_ORDER) ordered[k] = fp[k];
    if (globalThis.__dump) globalThis.__dump.fp_json = JSON.stringify(ordered);

    const codes = str2code(JSON.stringify(ordered));
    const ns_arr = str2code(pow.token);
    let encryStr = '';
    for (let i = 0; i < codes.length; i++) {
        encryStr += String.fromCharCode(ns_arr[i % ns_arr.length] ^ codes[i]);
    }
    let out = kdf_encrypt(encryStr, kdfConfig);
    if (globalThis.__dump) { globalThis.__dump.encry = encryStr; globalThis.__dump.cipher = out; globalThis.__dump.kdfkey = kdfConfig.key; }
    const half = out.length / 2;
    out = out.substring(0, half) + random_key_md5.slice(0, 4) + out.substring(half);

    // POST body 里的 timings 必须和 fp.performance.timing 完全一致
    return {
        fp: out,
        token: pow.token,
        browser_2: browser_2,
        timings: {
            connectStart: t.connectStart, secureConnectionStart: t.secureConnectionStart,
            unloadEventEnd: t.unloadEventEnd, domainLookupStart: t.domainLookupStart,
            domainLookupEnd: t.domainLookupEnd, responseStart: t.responseStart,
            connectEnd: t.connectEnd, responseEnd: t.responseEnd, requestStart: t.requestStart,
            domLoading: t.domLoading, redirectStart: t.redirectStart, loadEventEnd: t.loadEventEnd,
            domComplete: t.domComplete, navigationStart: t.navigationStart,
            loadEventStart: t.loadEventStart, domContentLoadedEventEnd: t.domContentLoadedEventEnd,
            unloadEventStart: t.unloadEventStart, redirectEnd: t.redirectEnd,
            domInteractive: t.domInteractive, fetchStart: t.fetchStart,
            domContentLoadedEventStart: t.domContentLoadedEventStart,
            jobStart: dyn.timeline.jobStart, jobEnd: dyn.timeline.jobEnd
        }
    };
}


module.exports = {
    solve_pow, get_params, parse_page, readBrowser2Template, extractBytecode,
    crc32, build_browser_2, getConfig, kdf_encrypt, md5, hash, FP_BASE, FP_KEY_ORDER,
};
