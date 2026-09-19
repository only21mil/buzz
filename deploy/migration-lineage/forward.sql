-- Requires Victor's approval. Run with psql -X -v ON_ERROR_STOP=1.
-- Reverse is valid only before any new migration has run.
BEGIN;
SET LOCAL lock_timeout = '5s';
LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE;
CREATE TEMP TABLE expected_migration_lineage (
    version bigint PRIMARY KEY, description text NOT NULL, checksum bytea NOT NULL
) ON COMMIT DROP;
INSERT INTO expected_migration_lineage VALUES
    (1, 'initial schema', decode('dbc16fbf139a47d526975a727e6349aa9800a8ffec0a9f040a7f4e545d413e50a32160171d4cb112bf3671823eea7075', 'hex')),
    (2, 'git repo names', decode('49c1e203577698af725d2db237e25da3cf928ba19b5a07cf14f2bcd1d22d486a3b53263f025040273e393be16145e270', 'hex')),
    (3, 'community icon', decode('d0953a3ac68d2c7c7305c91b0c3ac122bbdc7cc25de0a28f30462d2632d9ccf26256dfea031c0ff690f9e1b5c0dae17d', 'hex')),
    (4, 'events tags gin', decode('5c5108f23d2866cd30e10d15d10b9fa75383ac86985d1be0757f32e3dead6f7caecce30c499eea3221b4d114cd99df6a', 'hex')),
    (5, 'agent turn metric fts', decode('84cf1c768d80480a07bea5b43b83b83d2ff0c3809d2011dcfb751be6a34177c7aab67a9cc2ae8968f50a513edd7d8e83', 'hex')),
    (6, 'moderation', decode('9e5bbfa7469aefc0158f9f67208bdbd54c5eb3c821ae64f33fcbc2b38680afae47ab80d1fb5fda53f59cd8d68422c0d2', 'hex')),
    (7, 'nip rs retention', decode('939ac3ebe69d9db5dfe2e59ed1c9251270a27559fc74ad36aecf9761994c32e808f77220489322d37ce557c3de56cfca', 'hex')),
    (8, 'fresh install search allowlist', decode('f182146b6470c11c78bd4f6a285e078df6072958eb9f264d0432dd47b9e2889dd36287ca730100759542017f1786ed67', 'hex')),
    (9, 'nip rs database guards', decode('5797443ecc13ce7bd4cfd5707d8ce44a37e104b0fab0355b7c4d620667943ee357141610cf95bb5cb27f6a3d3020022f', 'hex')),
    (10, 'nip rs exact replay guard', decode('84748c2160148d3674f4e15325aedc19a8f7300b1f465b64d06ef0c43cb4c96412b41a99dab4a28db8247dc18072e383', 'hex')),
    (11, 'nip rs exact tag cardinality', decode('d6fcbfe79e22e7c73caee36cba13c7feb5daf690fdc6957264c897f25678deb8dd220a4b422030570d475fe14d63f342', 'hex')),
    (12, 'push leases', decode('b95c2e08388d1f698f62a3cce948ec108300fb3b4b2b719803ecbc4af4f8cc07d5ad75b61d7287d1a91aa020938b1d35', 'hex')),
    (13, 'push endpoint state', decode('6db1b972e28884665c49c5c926fb5464f104db853df311c97613e339b7ed82b847e120487c12719229be48ecb3635fc7', 'hex')),
    (14, 'push lease fts', decode('08755814a36a4f8494f7f48bce6d37a429b710a1902d0ed3569d5533b460cfd355098a3dad662320f9dd5cdec37ff0c2', 'hex')),
    (15, 'push gateway authority', decode('74c3b952090efe211d08da10a474de0e1ec9b02e2c22e6503210e45aff07de1667afc95cf0e10eb6b4bafe2f0864d906', 'hex')),
    (16, 'community archival', decode('39de24bdf7c26f172af58972993c379a50c81d8755187f23deabd9919ddba11c47faff3d69d2bdd42bf9096ca2441c81', 'hex')),
    (17, 'product feedback', decode('2788f2b8bf2347ccaea0d15bd602b863e1be721b2cc292d433bf64ca66cdbbb9fa87739e22eab94da03e4d34e7be426d', 'hex')),
    (18, 'push match queue', decode('f6a16ba98bf84174088684d19cc33b0efc436635723823f69429fafe1389b60e9432ceb7107afdc53900b46ffc4e47c9', 'hex')),
    (19, 'mesh status retention', decode('a9c2b378c0650bcaa9004f2f34a96b4eb41e02cdf6fc0797b128d706ce07bfa51725a66af63d9f5084d61e9a731c1049', 'hex')),
    (20, 'join policy acceptances', decode('06409e8657ce06941e1aca68049405d48beb23be83ac971fd6aee358e5eac119f579730d0e0904409abb43ce146124d8', 'hex')),
    (21, 'created at fence floor', decode('37d7ff757ecd2e6eda79830a80725efe81ca76eb46291891ebe0380ad3717dc58e9c1d203b656812dfda7d8ed2e9f2f2', 'hex')),
    (22, 'event ttl refresh', decode('82a015291aa8b9a50dbc8d7308a865b63140d39a5581694428b7d038086da8cceba7f6709db270fa8aac3d546e32da0f', 'hex')),
    (23, 'push match gate', decode('fb1876d1af9738342bc24b3e0ad8de73e45900786f15283e338d59c81f05548cef2734ffb2e243120aff23957310e0bc', 'hex')),
    (24, 'event ttl refresh shared lock', decode('aaf2084176d409cb63015acce2d4d13a730d3f8ca060d0fb262b6d1805b0c33c36a07528691af2240be76e2ea4fe61f3', 'hex')),
    (25, 'relay invites', decode('d4fdfc8bc8c9d75f7b812f40d533af80de1053fdd0d95c99b6ff6376e7d7090a8b514ef4e0e9d31aba258e6e7833b1c5', 'hex')),
    (26, 'replica heartbeat', decode('d08e2f660ed70d11a765c710d8c6cb448f6e151b3aa46b75ddd47be88f4df0f355e923794c25be2aa5d566a51a04059e', 'hex')),
    (27, 'channels id lookup index', decode('a0d196710d689af3f5b9d0257aee31aa2f435a06b8663c206a4d5cf819c979e3f36740d192901785e013a56e99447d9b', 'hex')),
    (28, 'long reaction payloads', decode('32ac3a3abf13343683edc353a361feee1d6b8ebb2d997805188599a0bde9b0a4aa18a99d61f47df41f5a1778bb9a261e', 'hex')),
    (29, 'workflow run snapshots', decode('b6dbaff039468e45d73c271837ab101cd9159ef7beb0a7d62b49e962936e47919f5846c3075f9acb4ecf35a9de754608', 'hex')),
    (30, 'workflow state', decode('dcead8897d24e149f49204e50d5288128ec5a85824e5e2f03f0e29639b1df3660b23ace520416c833c4b20789ff13052', 'hex')),
    (31, 'workflow approval foundations', decode('d0387fe23f3ce73b265b292d2c316b792ad91ad5519ccd7cb7614a0823fda35f7f2250134fb8250e548089f391d67292', 'hex')),
    (32, 'ci event storage', decode('0312074fb427b702a5c5f370e7b06ad15ec51c6488f040d545e64f5f6b7a6ed11f9ba84395b2ba963d6d83aa5f1faeaf', 'hex')),
    (33, 'workflow resume recovery', decode('c43fd9e80d84ceb16bbbacb27a037d2feab87919f0c2097405c848a201084fbadc01cfe2b9a741a71072060dd84da5aa', 'hex')),
    (34, 'workflow effect claims', decode('98c1b5b0d5432b298afa00f83f50a0d27902e929955702a3426e6774c6a7331744885ecbec8a3d188e2baae7eef0d831', 'hex')),
    (35, 'ci grants', decode('09467f5a17e44e8931088c2b2eda81e963ceeebd3ba588940ab8f910df9a2a385bc867a2c4cd8ba4fadd3165276bb08d', 'hex')),
    (36, 'workflow run error codes', decode('28a5aac2e1a6a4b7c7de4c61d760f5e132e511f085b4a952539df22d0835689d72b6231be2ffaa44e154d987646a40ff', 'hex')),
    (37, 'push message kinds', decode('d2247d99141ee99c5da55a973d9810c68e2a2566abd0b1e894312deb9e5ccad7d5b393f2c1d4b2736f3a7e0980252c6f', 'hex')),
    (38, 'push gateway dogfood profile', decode('ed55cbda5e3de7e5306b84481399e62b01ff88798f1b708d2d1614d4d9296f5babec17082339944f3eb7b9d8e26e5e7c', 'hex')),
    (39, 'channel admin audit actions', decode('2eb0a56da293cc9d85c246abf18601ecc5d64a8471a38e77ff1c10ab6f769ab8ff69bb1399d99dedd352070dcfaef30e', 'hex')),
    (40, 'agent drafts', decode('af619357f88765157a151571825319af5218860d4a51d9a733ff0cee518def67910fda7a7d1f426e0ddab1fd0d5b543f', 'hex')),
    (41, 'ci check storage', decode('fbc4fed76e4f67365b90c87017e04c05f03fec16b4e7912db5df7ae2fb7f83e599b5aa87d5f09366f722fe3c462849fd', 'hex')),
    (42, 'ci merge gate', decode('953c4b11335c54b6dcd44aff642518f2f75bdb6bc2466e1690e8fb2451302b8a634b9c9d99fd5650f48e8d4ac749aa90', 'hex'));
DO $$ BEGIN
    IF (SELECT count(*) FROM _sqlx_migrations) <> 42 OR EXISTS (
        SELECT 1 FROM expected_migration_lineage e
        FULL JOIN _sqlx_migrations m USING (version)
        WHERE e.version IS NULL OR m.version IS NULL
           OR m.success IS DISTINCT FROM true
           OR m.description IS DISTINCT FROM e.description
           OR m.checksum IS DISTINCT FROM e.checksum
    ) THEN
        RAISE EXCEPTION 'unexpected migration lineage; no rewrite performed';
    END IF;
END $$;
UPDATE _sqlx_migrations SET version = version + 1000 WHERE version IN (29,30,31,32,33,34,35,39,40,41,42);
UPDATE _sqlx_migrations SET version = 31 WHERE version = 36;
UPDATE _sqlx_migrations SET version = 40 WHERE version = 37;
UPDATE _sqlx_migrations SET version = 43 WHERE version = 38;
DO $$ BEGIN
    IF EXISTS (
        SELECT 1 FROM (
            SELECT CASE version WHEN 29 THEN 1029 WHEN 30 THEN 1030 WHEN 31 THEN 1031 WHEN 32 THEN 1032 WHEN 33 THEN 1033 WHEN 34 THEN 1034 WHEN 35 THEN 1035 WHEN 39 THEN 1039 WHEN 40 THEN 1040 WHEN 41 THEN 1041 WHEN 42 THEN 1042 WHEN 36 THEN 31 WHEN 37 THEN 40 WHEN 38 THEN 43 ELSE version END AS version, description, checksum FROM expected_migration_lineage
        ) e FULL JOIN _sqlx_migrations m USING (version)
        WHERE e.version IS NULL OR m.version IS NULL
           OR m.description IS DISTINCT FROM e.description
           OR m.checksum IS DISTINCT FROM e.checksum
           OR m.success IS DISTINCT FROM true
    ) THEN RAISE EXCEPTION 'rewrite produced unexpected identities'; END IF;
END $$;
COMMIT;
