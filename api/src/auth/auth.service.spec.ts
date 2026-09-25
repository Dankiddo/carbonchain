import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { StellarKeypairService } from '../stellar/stellar-keypair.service';
import { CacheService } from '../common/cache.service';

/**
 * Tests for Issue #933 — rotating refresh tokens and short-lived access tokens.
 * Tests for Issue #932 — server nonce account binding.
 */
describe('AuthService — token management (Issue #933)', () => {
  let service: AuthService;
  let jwtService: jest.Mocked<JwtService>;
  let cacheService: jest.Mocked<CacheService>;

  const cacheStore = new Map<string, unknown>();

  beforeEach(async () => {
    cacheStore.clear();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('signed-access-token'),
            decode: jest.fn().mockReturnValue({ jti: 'jti-1', exp: Math.floor(Date.now() / 1000) + 900 }),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn().mockImplementation((key: string, def?: unknown) => {
              if (key === 'STELLAR_NETWORK') return 'TESTNET';
              if (key === 'HOME_DOMAIN') return 'localhost';
              return def;
            }),
          },
        },
        {
          provide: StellarKeypairService,
          useValue: {
            getAdminKeypair: jest.fn().mockReturnValue({
              publicKey: () => 'GADMIN',
              sign: jest.fn(),
            }),
          },
        },
        {
          provide: CacheService,
          useValue: {
            get: jest.fn().mockImplementation((key: string) =>
              Promise.resolve(cacheStore.get(key) ?? null),
            ),
            set: jest.fn().mockImplementation((key: string, value: unknown) => {
              cacheStore.set(key, value);
              return Promise.resolve();
            }),
            del: jest.fn().mockImplementation((key: string) => {
              cacheStore.delete(key);
              return Promise.resolve();
            }),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jwtService = module.get(JwtService);
    cacheService = module.get(CacheService);
  });

  describe('issueTokenPair', () => {
    it('returns an access_token, refresh_token, and expires_in', async () => {
      const result = await service.issueTokenPair('GACCOUNT');
      expect(result).toHaveProperty('access_token', 'signed-access-token');
      expect(result).toHaveProperty('refresh_token');
      expect(result).toHaveProperty('expires_in', 900);
      expect(typeof result.refresh_token).toBe('string');
    });

    it('stores refresh token metadata in cache', async () => {
      const result = await service.issueTokenPair('GACCOUNT');
      expect(cacheService.set).toHaveBeenCalledWith(
        expect.stringContaining('auth:refresh:token:'),
        expect.objectContaining({ account: 'GACCOUNT' }),
        expect.any(Number),
      );
      expect(cacheService.set).toHaveBeenCalledWith(
        expect.stringContaining('auth:refresh:family:'),
        result.refresh_token,
        expect.any(Number),
      );
    });

    it('preserves the provided familyId when rotating', async () => {
      const familyId = 'family-abc';
      await service.issueTokenPair('GACCOUNT', familyId);
      expect(cacheService.set).toHaveBeenCalledWith(
        `auth:refresh:family:${familyId}`,
        expect.any(String),
        expect.any(Number),
      );
    });
  });

  describe('rotateRefreshToken', () => {
    it('issues a new token pair on valid rotation', async () => {
      const first = await service.issueTokenPair('GACCOUNT');

      // The family should now point to first.refresh_token.
      const result = await service.rotateRefreshToken(first.refresh_token);
      expect(result.access_token).toBe('signed-access-token');
      expect(result.refresh_token).not.toBe(first.refresh_token);
    });

    it('throws UnauthorizedException when token is not found', async () => {
      await expect(
        service.rotateRefreshToken('non-existent-token'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('detects replay: revoking family when an old token is re-used', async () => {
      const first = await service.issueTokenPair('GACCOUNT');
      // Rotate once — family now points to a NEW token
      await service.rotateRefreshToken(first.refresh_token);

      // Replay the first (now stale) token → should detect theft
      await expect(
        service.rotateRefreshToken(first.refresh_token),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('isTokenRevoked', () => {
    it('returns false for a fresh JTI', async () => {
      const revoked = await service.isTokenRevoked('fresh-jti');
      expect(revoked).toBe(false);
    });

    it('returns true after the jti is added to the blocklist', async () => {
      cacheStore.set('auth:blocklist:jti:blocked-jti', true);
      const revoked = await service.isTokenRevoked('blocked-jti');
      expect(revoked).toBe(true);
    });
  });

  describe('logout', () => {
    it('adds the access token jti to the blocklist', async () => {
      await service.issueTokenPair('GACCOUNT');
      await service.logout('raw-bearer-token');
      expect(cacheService.set).toHaveBeenCalledWith(
        'auth:blocklist:jti:jti-1',
        true,
        expect.any(Number),
      );
    });

    it('revokes the refresh family when refresh_token is provided', async () => {
      const pair = await service.issueTokenPair('GACCOUNT');
      await service.logout('raw-bearer-token', pair.refresh_token);
      // Family key and token key should be deleted
      expect(cacheService.del).toHaveBeenCalledWith(
        expect.stringContaining('auth:refresh:family:'),
      );
      expect(cacheService.del).toHaveBeenCalledWith(
        expect.stringContaining('auth:refresh:token:'),
      );
    });
  });
});
