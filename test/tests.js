'use strict'; // for node 4
const hydrogen = require('../build/Release/node-libhydrogen-binding');
const expect = require('chai').expect;
require('mocha');

describe('hydrogen.init', () => {

    it('should init correctly and return zero', () => {
        expect(hydrogen.init()).to.equal(0);
    });

    it('should be callable multiple times without errors', () => {
        expect(hydrogen.init()).to.equal(0);
        expect(hydrogen.init()).to.equal(0);
        expect(hydrogen.init()).to.equal(0);
    });

});

describe('hydrogen.random_...', () => {

    it('should not yield the same random number twice in a row', () => {
        for (let i = 0; i < 1000; i++) {
            expect(hydrogen.random_u32()).to.not.equal(hydrogen.random_u32());
        }
    });

    it('should respect the given boundaries', () => {
        for (let i = 0; i < 1000; i++) {
            const rand = hydrogen.random_uniform(2);
            expect(rand).to.be.lt(2);
            expect(rand).to.be.gte(0);
        }
    });

    it('should throw on illegal argument type', () => {
        expect(() => hydrogen.random_uniform("test")).to.throw();
    });

    it('should throw on argument count mismatch', () => {
        expect(() => hydrogen.random_uniform(1, 2)).to.throw();
    });

});

describe('hydrogen.secretbox_keygen', () => {

    it('should generate keys with the buffer type', () => {
        const key = hydrogen.secretbox_keygen();
        expect(key).to.be.instanceof(Buffer);
    });

    it('should generate keys with the correct length', () => {
        const key = hydrogen.secretbox_keygen();
        expect(key.length).to.equal(hydrogen.secretbox_keybytes_size);
    });

});

describe('secret key encryption', () => {

    const msg = "message";
    const key = hydrogen.secretbox_keygen();
    const msgId = 0;
    const context = "testtest";
    const invalidContext = "invalid context";
    const keyWithInvalidSize = Buffer.alloc(5);

    describe('hydrogen.secretbox_encrypt', () => {

        it('should expose the constant for contextbytes length', () => {
            expect(hydrogen.secretbox_contextbytes_size).to.eq(8);
        });

        it('should expose the constant for keybytes length', () => {
            expect(hydrogen.secretbox_keybytes_size).to.eq(32);
        });

        it('should expose the constant for headerbytes length', () => {
            expect(hydrogen.secretbox_headerbytes_size).to.eq(36);
        });

        it('should encrypt something', () => {
            const ciphertext = hydrogen.secretbox_encrypt(msg, key, msgId, context);
            expect(ciphertext).to.be.instanceof(Buffer);
            expect(ciphertext.length).to.be.equal(43);
        });

        it('should decrypt encrypted messages correctly', () => {
            const ciphertext = hydrogen.secretbox_encrypt(msg, key, msgId, context);
            expect(hydrogen.secretbox_decrypt(ciphertext, key, msgId, context)).to.equal(msg);
        });

        it('should detect forged messages', () => {
            const ciphertext = hydrogen.secretbox_encrypt(msg, key, msgId, context);
            ciphertext.set([1, 2, 3], 3);
            expect(() => hydrogen.secretbox_decrypt(ciphertext, key, msgId, context)).to.throw();
        });

        it('should detect invalid context lengths', () => {
            expect(() => hydrogen.secretbox_encrypt(msg, key, msgId, invalidContext)).to.throw();
        });

        it('should detect invalid keys', () => {
            expect(() => hydrogen.secretbox_encrypt(msg, new Uint8Array(5), msgId, "test")).to.throw();
        });

    });

    describe('hydrogen.secretbox_probe', () => {

        const ciphertext = hydrogen.secretbox_encrypt(msg, key, msgId, context);
        const probe = hydrogen.secretbox_probe_create(ciphertext, context, key);
        const probeWithInvalidSize = Buffer.alloc(5);

        it('should expose the constant for probebytes length', () => {
            expect(hydrogen.secretbox_probebytes_size).to.eq(16);
        });

        it('should generate and verify probes', () => {
            expect(() => hydrogen.secretbox_probe_verify(probe, ciphertext, context, key)).not.to.throw();
        });

        it('should throw on invalid probes', () => {
            const probe = new Uint8Array(hydrogen.secretbox_probebytes_size);
            expect(() => hydrogen.secretbox_probe_verify(probe, ciphertext, context, key)).to.throw();
        });

        it('should throw on invalid context size when creating a probe', () => {
            expect(() => hydrogen.secretbox_probe_create(ciphertext, invalidContext, key)).to.throw();
        });

        it('should throw on invalid key size when creating a probe', () => {
            expect(() => hydrogen.secretbox_probe_create(ciphertext, context, keyWithInvalidSize)).to.throw();
        });

        it('should throw on invalid probe size when verifying a probe', () => {
            expect(() => hydrogen.secretbox_probe_verify(probeWithInvalidSize, ciphertext, context, key)).to.throw();
        });

        it('should throw on invalid context size when verifying a probe', () => {
            expect(() => hydrogen.secretbox_probe_verify(probe, ciphertext, invalidContext, key)).to.throw();
        });

        it('should throw on invalid key size when verifying a probe', () => {
            expect(() => hydrogen.secretbox_probe_verify(probe, ciphertext, context, keyWithInvalidSize)).to.throw();
        });

    });

});
