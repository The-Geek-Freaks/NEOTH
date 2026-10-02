#!/usr/bin/env python3
"""Fail closed on the reviewed Matrix 0.18 backports before Cargo acceptance.

``validate_sources`` is the only pre-resolution entry point: it authenticates
both official crates and permits only the explicit reviewed postimages.
``validate`` is final acceptance and also requires the regenerated workspace
lock plus the two synchronized, time-bounded RUSTSEC-2026-0318 exceptions.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime, timezone
import hashlib
import os
from pathlib import Path
import sys
import tarfile
import tomllib
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
SRC = Path("SRC")
MANIFEST_RELATIVE = SRC / "Cargo.toml"
LOCK_RELATIVE = SRC / "Cargo.lock"
AUDIT_RELATIVE = SRC / ".cargo" / "audit.toml"
DENY_RELATIVE = SRC / "deny.toml"
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
ANYMAP3_CHECKSUM = "fb5dfbc6d8d2675589ccbe4d0fd61df2419075625f8c1a62325e718e2b0049f9"
ADVISORY = "RUSTSEC-2026-0318"
EXPIRY_DATE = date(2026, 11, 1)

SDK = "matrix-sdk"
CRYPTO = "matrix-sdk-crypto"
VERSION = "0.18.0"
PACKAGES = {
    SDK: {
        "vendor": SRC / "vendor" / SDK,
        "archive": Path("packaging/vendor-provenance/matrix-sdk-0.18.0.crate"),
        "archive_prefix": "matrix-sdk-0.18.0",
        "checksum": "7083d580527511ac5d9369e03b9f2b20902e76949f1b3964051f978e4d3756ae",
        "upstream": {
    '.cargo_vcs_info.json': '3222874ff733b64cb21a9afbf3fd8ad36d01f557c2560afc0bc7a0d625cab48b',
    'src/sliding_sync/mod.rs': '0a9e350a3a64d7176e6ecfba61dde7b03cfb77c47509864dfa43088847b82130',
    'src/sliding_sync/README.md': '9f357d2a2145fe05ef8fd33486450a29e1d751595068a33effc14846bb2189fd',
    'src/sliding_sync/list/builder.rs': '96e7d7039dd50b48fc436549b7d05fb4788e5f0892de8bbb657f5e0d684462db',
    'src/sliding_sync/list/frozen.rs': 'd8bd35959235f25e17139ef5719add55fc3857ff141ce7fa1c9a8a21451b2697',
    'src/sliding_sync/list/mod.rs': 'c039b233d6832b3baee653ac8e18366df004fcf36990e225344eed7419416461',
    'src/sliding_sync/list/request_generator.rs': 'f027739f130ce934a7a1a890e45d5aac677e54fc55718db6273422051b88b5ba',
    'src/test_utils/client.rs': '24e1c601d7832603f1cb06cecaa451f7afb43360b4ee5f753d48170149d37796',
    'src/test_utils/mod.rs': 'e708c1c48d19e2f8d427193ff95937ac1d597683a9d2ae7d7afc52ebba62bf5b',
    'src/test_utils/mocks/encryption.rs': '221261ed60399f40a6bfb35bc9e106714c75c3d76c6e6a5d7576d6489b582e99',
    'src/test_utils/mocks/mod.rs': 'fd2fc72d033a4061b640528ab52bb1c3ea183d85ae26c79546c1bcfb316aa12b',
    'src/test_utils/mocks/oauth.rs': '9b83f08a571d867fa376d140caae01e0402aa78c009fabcb6aa8a3135dbe43fd',
    'src/utils/local_server.rs': '8a608c83f876f1bae5622a33e237af060e2e72b3469be24465cd0fbb39dae21b',
    'src/utils/mod.rs': '1e9296342eb625fe48e5d4b2bce2a893994883756e128cf0d4394b6666a17ab1',
    'src/widget/capabilities.rs': '7a47019228bcda4cdf8450fe01860b7035cdb234573835c24a0749e6ed01f0ba',
    'src/widget/filter.rs': 'adfb60404499a4640f6c6727ac3afd2b3621d821dd457a9bec0c248e36305ddd',
    'src/widget/matrix.rs': '28f1f07ecdb2905e54104362b24ff5c862ffd9ebd0a970ca81edf3edbc2e83df',
    'src/widget/mod.rs': '1c9b05f3e29f9c333aee32a8d2f0666cccabb29a0c5433acff61201d909af2c1',
    'src/widget/README.md': 'a85f1fd2775e4cab31f5224d9e4f79fbcc99eec83e3be8f9e54134b81248fb71',
    'src/widget/machine/driver_req.rs': '8035f10794ff5f5107dfe9966a8f656bf1e6834a51ecebc051da349f6859f682',
    'src/widget/machine/from_widget.rs': '256dee5d5b07d9a91acecb7fb74c1293294dd2e3dc5ea30b9375f12ce8d2f60a',
    'src/widget/machine/incoming.rs': '3e0ab7b8f08894f8bae6e6af2e78ee254afcb4c34cd121ed9ff64ca87963e609',
    'src/sliding_sync/error.rs': '73047b01016b3a20144a20071972943b1f40c4c49805ded1edb3d30f5ae4374f',
    'src/sliding_sync/client.rs': 'ef4b22636fdf7dd02ee1c4460200b44cd7a4398d81f7286f9ecfde2ef31a288c',
    'src/sliding_sync/cache.rs': 'a289f971f432f29540158380a41d74626861bc9b60559c2350dd723ddf0022ac',
    'src/sliding_sync/builder.rs': '133414eab682e1586a4df446123e9fac53ad2786678d4a1f814667cb420f7c20',
    'src/notification_settings/mod.rs': '3812590c5777a87468078a09c5e12ab4109f24791583f7cadb7aed73fc815109',
    'src/notification_settings/rule_commands.rs': '3b6929da4fa951bd8c34ea83d6488f618a8101a6dc839e1c5aa748dc94dd9f34',
    'src/notification_settings/rules.rs': '4d29771c6b831c18742c040e4ecb3d7931649eb8d1ab30aeda68b9afe5273136',
    'src/paginators/mod.rs': '578ee5428fdd46ccdaf35000c11dff61fec985fba2b2085744489c20ee5bc66b',
    'src/paginators/room.rs': 'c34529e007862da7fcbc7a84bab04781cfad98ee6aae425d968003aa99fb5139',
    'src/paginators/thread.rs': '201d60253d89f45daf9b8d0180d9287b02f8e45aff3025649e470734e74a332d',
    'src/room/calls.rs': 'c94b829cfcb4a9ce0a313c5a537051a5465606977971035d466c524709196259',
    'src/room/edit.rs': 'eb17655608b7ffabd7f0cdcc99a4647d6f238ac21abf5d7490a8c5e64cd015c5',
    'src/room/futures.rs': '058a0ceefc40c57eef6ec0d41dfef1e64ad4738f74e72deaec917d8b2c69ca30',
    'src/room/identity_status_changes.rs': '8a383fc3adc5f45861f488bf39dc9079da895e9e8acfa25f0bf3e4825f984b04',
    'src/widget/machine/mod.rs': '560b537c1497871ac01e3aa356509b846ab9fe62e7b975527e41caf553f74102',
    'src/room/knock_requests.rs': '669e9c37d59907d2739c7f83c26fa9fe72574196de7d1b181b0e68fb46932330',
    'src/room/messages.rs': 'f9efd1445aea6cfe49dd41620c1e6e6e9db6ea30c0c5b67377f30cacf9154437',
    'src/room/mod.rs': '5df7d880ff9b6a8c90e49d08db59874f45070f75e4c8331cdf22b0accaca3594',
    'src/room/power_levels.rs': '6d890cb06444591c7cc79d5d9d97ec4de28a21d37ab376c4beadf3e865b6314b',
    'src/room/privacy_settings.rs': '7af3b6f5fb873f397cb5e668ab069a753d1917f1f8b0188268a85dff9dcf9b91',
    'src/room/reply.rs': 'dd62dbb35ceb922a825f45395627876d02f6868701e3b09b9316a3c75d408bab',
    'src/room/shared_room_history.rs': '3a506a88773dbdba549fee07024cb410fdadd2dd0cc4f2cb3d3c6776cb83b6bb',
    'src/search_index/mod.rs': '7899ae38171ed267d4f5c3c5d03dcaba87aeebaed2bf5edbcbd344af276ab492',
    'src/send_queue/mod.rs': '1518ea882423dbfd0843876d34742bfbdad446561c99926c44c9692475d7f0f6',
    'src/send_queue/progress.rs': '51f40299620b8501bab5b163f48356b76f3f3fae05c2e40c6eee4f2728768775',
    'src/send_queue/upload.rs': '5a675a45a2f8d31f4a01af49a203c3cfd5e5670f102ef8067354c932e1468bf5',
    'src/room/member.rs': '2a64b39449425d6f890bbc9f6539815548b4fd53dbd7623b5629c83c6fbb7417',
    'src/notification_settings/command.rs': '2f16fc7b407772cd21398eef71da3d77b66bf46e334309d33f11271411f920b2',
    'src/widget/machine/openid.rs': 'e490d966ae10fd0ce6c22a499f98b7bbf7b3d1e0073621c84353955eeca8d590',
    'src/widget/machine/to_widget.rs': 'ef770d4d45ee87feefbc2c181f43413b9af4eb5cdbb2a47ceb982cb7c194f914',
    'tests/integration/encryption/cross_signing.rs': '78dfbd48dfed804668b5513ebcfeb9e2539cb601338c5c073070d725d891b8a0',
    'tests/integration/encryption/recovery.rs': '16aee38541e01d8c384cec94fbc681a68fa7c0b7027890316b523f4e490ea939',
    'tests/integration/encryption/secret_storage.rs': 'f3f7809f5419751c3b7b1b8e1f5595bc0cac7697f6a12855f3444f97d35661ec',
    'tests/integration/encryption/shared_history.rs': '15ad1b440af4affbbae82c04bc76343b38e9499725db91eb1fb3aa10751d074c',
    'tests/integration/encryption/state_events.rs': '34b8ba7ef9f575fbf166fd7cabbd296b97b060cfd65ba1ec986b87d89e57d13d',
    'tests/integration/encryption/to_device.rs': '4e5eb34f7636ad1066491d2124c12cd477812163114c2d9b1ae44fa11f5a1376',
    'tests/integration/encryption/verification.rs': 'a07940fa4f5868927f40050ca6b1f309f2b72e5cd8f97aa4ad5e49017d80bdb6',
    'tests/integration/event_cache/mod.rs': 'ead5972fefaafbc017fde2890a3f98d69bda71af72c508c50c8385f9edb1d73a',
    'tests/integration/event_cache/read_receipts.rs': 'f504b08765d24b470474df1bca399135fe6b8d3f709a28f9f96fc0306eb2ea9c',
    'tests/integration/event_cache/threads.rs': '11e92d362b197daf77cc0a757c7390d27c0055b9501082c90e72461bf222c776',
    'tests/integration/room/calls.rs': '3e6519b26f4a037b7455022529da22d2cc91cf70ba28743f3b3a438b5b7008e6',
    'tests/integration/room/common.rs': 'b3c95e64ed9db3c1124bd1573e8e4994556dc32b8f7af85c6158a41929442c9c',
    'tests/integration/room/joined.rs': '9a18cfb692ecd8964ef9ed846af7ded938f7733cc608b6efe3b6cee56dde107e',
    'tests/integration/room/left.rs': '53f706686a03db47c3ff3d852585d3eb6d284870bb671d3ae291ff436ca03012',
    'tests/integration/room/mod.rs': 'fd14f3ef335e1d14d5b2a460a7b902849496f29ac1f963139fd29710a5d14604',
    'tests/integration/room/notification_mode.rs': '744dfea970b2c0c0b599f459975f786644a8cb2a0b83a8a98475de6a3dc5f6cd',
    'tests/integration/room/pinned_events.rs': '7f741b5feceb763b50608f6725806be3d0d7e663327141ace2a96fdbee805513',
    'tests/integration/room/spaces.rs': '6f472fe0316b6caabfeaae2998b03337e29c66c96d789f995031325ebaeee73c',
    'tests/integration/room/tags.rs': '426a1ecb89af87e26e6e45018f57ced9e9140998a4d7349eb32a387a3ca27fb1',
    'tests/integration/room/thread.rs': '4088ac6e45dd3a8c31507d4b6dd0bfbdbd358baa7b16bde22f5337366d115436',
    'tests/integration/room/attachment/mod.rs': 'cd6bae25fd86a47e8751f5740013438f232767323edbf275d345c2b957352e21',
    'tests/integration/encryption/backups.rs': '6408f633bd4503568b616a7be031641e769375d9f362df7207a694460ec8d969',
    'tests/integration/widget.rs': '27f641f815f8713ca2e4de6faa49a00d9881393ffda74df908f5ee574055079d',
    'tests/integration/sync.rs': 'ca3ea4dea0fff1455b7988ebe806f1f613a9a8af9053decfc06d87b1d7b9688a',
    'tests/integration/send_queue.rs': '20a0b7bbcf059745c9942d7ab18dc7e565fe9222592a8e7f53be57e117bec25a',
    'src/widget/machine/tests/api_versions.rs': 'e3ccd2f42713a95138bd921cda9aeff5976d9d7ea5b959d373329efe585dd8c7',
    'src/widget/machine/tests/capabilities.rs': '8f9b939f3e1dc677e5648dcaac1cc3ad4272be76b06e52d5d956189547b25d3f',
    'src/widget/machine/tests/error.rs': '715416f3fa84169cbd6b60d9163486f348e40f0947ebb122f9b11c48f0089314',
    'src/widget/machine/tests/mod.rs': '274d068cff1a737d68734ef714b4e1a4ebca4dbe883a9a7bc11e81e7286778e4',
    'src/widget/machine/tests/openid.rs': '938745bd7ce8a76bbf935cd69ad7275c49946de9f00fe6472298157caa65fa27',
    'src/widget/machine/tests/send_event.rs': '38165a16aaa7e7653022df5ba0e2181b06a2bde58a4d57e0e620f71ef38ce4ec',
    'src/widget/settings/element_call.rs': 'ccfe6a8b8cb6b384608528498ba842411930cf05d062431751e5fed371581d28',
    'src/widget/settings/mod.rs': '36a1cb25e6c0b9a9b3a81e8f86309b8f6cec14f2998a3768f0ae98494321b615',
    'src/widget/settings/url_params.rs': '294c4a81683243990851e0af6e3c151ff3a48dd4056ea7bb057d42b011949ee5',
    'src/widget/snapshots/add_room_id_to_raw_override.snap': '7fba5f42902b051152d1ee6e047296d9c7da857b13dc37f138aae20a3ee613e2',
    'src/widget/machine/pending.rs': '230a2fbf3f1c9f69195c7c8d41da69aaab4cdbee982d5128437c7dbcef1917c9',
    'src/widget/snapshots/add_room_id_to_raw.snap': '7fba5f42902b051152d1ee6e047296d9c7da857b13dc37f138aae20a3ee613e2',
    'tests/integration/client.rs': 'edf9357f911e658b7b76402cb54e16da0cc5f764eb3ba475610cbee93e9dbe51',
    'tests/integration/edit_validation.rs': '5970f1d9bb834ec04c6f10e545c253eb048df7b3eeaffc9826d7a38e31897ed2',
    'tests/integration/encryption.rs': 'b9466fd24bcf9c77816272f3abd2221b5df374f1ffdf22552e2c3c9614c0b2f4',
    'tests/integration/latest_event.rs': '4f04ac64168504f9c184eaff5172ae81944f9fdcda62e7e2f7674b39218673ae',
    'tests/integration/main.rs': '594ba2d8c000cb9173e2e86f83acb2425ec34c4623f9b7c9c9359d1b47662583',
    'tests/integration/matrix_auth.rs': 'b44299bfcb0cadf68a01f786c897aaa3fbceb5882feedd491bfea05824ef633f',
    'tests/integration/media.rs': 'cc42a034902135c43a5a1c9b91521a22fb0b805a4e3f5b1583b20f3ae686c293',
    'tests/integration/notification.rs': '96ba6b4657e81a9863794a7f8cbfee43d35e88d74024d281b99d385707f9631c',
    'tests/integration/refresh_token.rs': '31b06b4d4f4f45a806ad6cf6b2c887266b64af8bbae4de69624c4138376cf7ce',
    'tests/integration/room_preview.rs': 'e46bb0912b9e066f1e57deeaf867dba4bab04e79123415df3b788e6328b7cbb6',
    'tests/integration/account.rs': '3a1e06c28463b67717b96aafb6bf9440b0313952205ef81b2ccf2c9979d3766e',
    'tests/integration/room/beacon/mod.rs': 'cba6574fa62ccbb0bd80f8921d03916a8a9df143458abba7c689d002264cd7d0',
    'src/latest_events/latest_event/mod.rs': 'c3e61512dcb2bd649b09c82096864515d40c0cfbf80a44ccb2e033c51faafc5d',
    'src/latest_events/room_latest_events.rs': 'e7937e643414c35dc228ded562e0cc65b4c4ccbdbe0576c0ba833702b91c7b93',
    'src/authentication/oauth/http_client.rs': 'e667b32b158a77832b08fdbbb3e1ecc4d6b133b25ce594634ca46023358b394c',
    'src/authentication/oauth/mod.rs': 'b61dc26929b93cf183992e9ea7eecef8095b44e8cc2a9a3ccef67786ec421a8e',
    'src/authentication/oauth/registration.rs': 'bd0c9003c2f7f4e322322b69ddce1fd7f6a76679e9bdc2bda17fe9c994c682a3',
    'src/authentication/oauth/tests.rs': '13cc273fed16b63b9753e1882b01c0cbd564be379ecfb86f6bf48804bfe13120',
    'src/authentication/oauth/qrcode/grant.rs': 'a2f350e128a1793e9c91d7782079cffecb27b114c3b3650398448b4ab32d7c4f',
    'src/authentication/oauth/qrcode/login.rs': 'c24767f74b0256e4aac823905ce5f9d9d5590c4e3bad2423bcc39525207f9b3c',
    'src/authentication/oauth/qrcode/messages.rs': 'bee7db488edf64f12fc1fd0d37bb340118c7465d21e4cd1f2923287d03e22e04',
    'src/authentication/oauth/qrcode/mod.rs': 'ee457e591289998602e4e66254be8713a14b660cf359243db9112a2e923a8969',
    'src/authentication/oauth/qrcode/rendezvous_channel/mod.rs': 'f9312c96ebc607cd70bedf457807ba6a41dc1c909bfeae325ed0a7be34028823',
    'src/authentication/oauth/qrcode/rendezvous_channel/msc_4108.rs': '4ba60e9a5de27efb1dbf0da1c96d354c3638688cc0bc3c8b4e4905cf77782922',
    'src/authentication/oauth/qrcode/secure_channel/crypto_channel.rs': '459819e8da8fe926af123fac0f7922cf291fa0f859d50b7babf5d2f2e339e63b',
    'src/authentication/oauth/qrcode/secure_channel/mod.rs': 'd741233ad3f6330123315b987dd742b8513e227e203bc3ca789e3f11d80793fb',
    'src/client/caches.rs': '4d5e4fa7b05a2eb92a4fa711301ccdb904782089e78996be06fd0ce3e08d7ec6',
    'src/client/futures.rs': 'b32618385db1143a9e811965a57e0bc5f52a7d143185bbf79286af47e778c83b',
    'src/client/homeserver_capabilities.rs': 'd9719c28fafabec7773bbc114d562bfbf09c71b77df8104d2b269a7bd5abb197',
    'src/client/mod.rs': 'c7bb43a406b790a0c337f792796b9075d479e06786ae8728d14498b933dcfaeb',
    'src/client/thread_subscriptions.rs': 'eec10515bfc9f828bced0dd9352e3efec682e7a5fc95a88a87c7d29d64e90237',
    'src/client/builder/homeserver_config.rs': '3ab7adcc33d3617a885d0473fa639267d77d686aaede5ba851d8cd55faceb9bb',
    'src/client/builder/mod.rs': '1c8503b14010ea4b03542837d9df942e9ac05ad81046df7bf35407107e1a2331',
    'src/config/mod.rs': '14c4e4863df5db415075b1688763e1b99c8af2276ae438c6d37946855ad58e3e',
    'src/config/request.rs': '19054666cf1fa3d5a0110acb632331417150ee1fa240dde4f63a04444102acaa',
    'src/authentication/oauth/error.rs': 'fabee5487ea51dae50f01439317cfb4549d1454d35a51e1d1773d0ab49ddfe6f',
    'src/authentication/oauth/cross_process.rs': '352beab4764d26bc80b7923e0e3e3cf75a18b907cb89a3019d87329ca26c52e6',
    'src/authentication/oauth/auth_code_builder.rs': 'aa06cfc8f06012b5581a5b2269bf052351d790e4c6d9f4acf769890edadc9755',
    'src/authentication/matrix/mod.rs': 'f417123495ef4f777c01935fc765808d9c226bc72a69cb76c97be9449975e7c9',
    'build.rs': 'b6b40ffe56a71ec45fef7f54bc1059c0c935b8ded7458b86a193cce92e90a200',
    'Cargo.lock': 'dd30f4b99fe8ad212fca361ca68b2583ddcf806804dbda5845ccbeea299d3ebd',
    'Cargo.toml': '31dfb7405ce7d7074650fd7810627dee9c78ddd3e81fb183547becc337d242f4',
    'Cargo.toml.orig': 'd937a0bdd0e26268438d936bf1e9a8d14bcecffc190b5fc2ac66c612b9d5bef2',
    'CHANGELOG.md': '45da510ebf8bf764a958131613acb487589f1c7e7ba65e6f571daa04a85c1ac7',
    'README.md': 'bd261899277e53eef8582be9bc1de28c9fd23c554e6ed65f192e49ee569c0169',
    'uniffi.toml': '1a294d0e48f8abf54169910c75166eaf8413da36cf9f9edc84bd28070d69d441',
    'changelog.d/.gitkeep': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'src/account.rs': 'c42fe74bf08047fcf68b29bc0c7542af0696d6f7369c0e2c698fecb623b7fa3b',
    'src/attachment.rs': '6812fedf21288c1a161bf2dfaf164752fd17337027d6f15787eb38200cc86cab',
    'src/config/sync.rs': '01949fe63e1a05759b878ac0a99fc360d7da05df32b564a14b91525852745bae',
    'src/deduplicating_handler.rs': '656eb96c2b64c1d3352eaad9dcb1052eaeba5cac9e87a15113fb370122727cb8',
    'src/lib.rs': '880a03cc940d7b218507739a8bf533d8ddf70183ee8b893adff2afac67148b53',
    'src/live_locations_observer.rs': '2f3033f5c3756d71a636b0dc00d77a29316a8ca5e8afdb3a2fb3434662b2fa16',
    'src/media.rs': 'f2f2df4ddde011ce315636dc5d76713d1520b6d48885f5f3d5a39f920c2afacb',
    'src/message_search.rs': '6d6b84820ed22f04f5cf80508b66ee9cf26975c44e0a743c863949896a137a47',
    'src/pusher.rs': 'fa444cd79d9e0948fcb26dea6cfc31b709fabedd25aeafd709eb24f30b6d6ccd',
    'src/room_directory_search.rs': 'd746f2d5c8b184ef3eff6627d8e31f0710482d527176c8e233d0caf7e9011177',
    'src/room_preview.rs': 'e0fda0d8c3d2b40a9196e1264a9fac55cdb2ed4fc0fb21782b9a20f86a01e1a1',
    'src/sync.rs': 'bec31b9863e701f1f1ed5058d0cb55cdaee6120f0ffe8bcdc381f01dd764ae75',
    'src/authentication/mod.rs': '8abf6b1617ac2b1e54a8347feffba1d832a022bae8baac66ac8b21c1a90d4748',
    'src/authentication/matrix/login_builder.rs': '4e6835172ec3da44148321d4ff3e2ad189ec08fbbc9e13e6fe6b58da7476ce6e',
    'src/error.rs': '67c7e1237d485965113e079ea5c474a9d8564618b5e0a60fec52ff164c62897b',
    'src/latest_events/latest_event/builder.rs': '1ff4106493a9bc2c5d75847d6840c1cfaf5066f5dd78621bfb7e326e1604792e',
    'src/docs/encryption.md': 'e711e1987eb99ea40b9c7ff563af684823a09e03ee08292ac158d87d344bc4b8',
    'src/encryption/mod.rs': 'a96b9858c5d9d1ede37c9f66c0572d43b646aeaa2979381d16c59c1d1287528e',
    'src/event_cache/caches/pagination.rs': '3b5ba20bef971c9c49eb263234ffb5cdca8fd7f8599361f963a594fdfbeb830e',
    'src/event_cache/caches/read_receipts.rs': 'd3e8ba86dae80afc3465fdd89e2a28f5005f2d6bd619670844e653dfd4319f4f',
    'src/event_cache/caches/event_focused/mod.rs': '7a680fa29874127c75a37bfd3ed54cb41545b0d8d92066c6e68c2483f0b38626',
    'src/event_cache/caches/pinned_events/mod.rs': '8799136144c871576c349473c8a26f06c702178257ca16b1ead6b2b773cb893d',
    'src/event_cache/caches/room/mod.rs': 'c9d8bcd8c047e11c4f5f2dbed09232f173c1939653a9264ab0c4e64fc4ea7dad',
    'src/event_cache/caches/room/pagination.rs': '26aebbbf0bb4155ac2e62c94c4cc0baccc43b01189fd2c776b93a9668d78fc4b',
    'src/event_cache/caches/room/state.rs': 'e756ddc3428d0741f6ae62b2b54cc8a7d31b6f71da20dd32c81eea98d3f43c9a',
    'src/event_cache/caches/room/subscriber.rs': '72aa684b60980733bc6776f85f70dbfece7cfa44696c075414091aac85f339c7',
    'src/event_cache/caches/room/updates.rs': 'ae9df7d7ca79e272109b5a035770c6999c307820c133206c1dcd39f1354bc27f',
    'src/event_cache/caches/thread/mod.rs': '998b12003a650dd88379e78fcc27e415290e7846047d1163c25f74ba35b04a9d',
    'src/event_cache/caches/thread/pagination.rs': '19036a8a88411d596b80a12a584bd42c00ecee419a57201ada83996a2bed9336',
    'src/event_cache/caches/thread/state.rs': '410735a3b0cf410556e56eb3379b3888dce14a7a9b8eb97ad9b5a5b5e643dd5b',
    'src/event_handler/context.rs': '528f683d8489ef9cb13ab0572018e2d966435425c0b3e4e32630357f8e85008b',
    'src/event_handler/maps.rs': '37f9cef2fab6e80f6bf2c9ee5f4840f9ba1b741c8d0725acc1cd3152639c465e',
    'src/event_handler/mod.rs': '0c29f6941bb97fc5cc115df745888b2e36022f78c346e01cb8c74b635d1835e4',
    'src/event_handler/static_events.rs': 'd087afcaf6797a3ef89e9d9d17a710f2ad83ec9515a297eff9a61815e52c6bfe',
    'src/http_client/mod.rs': '22098fdf1a1f94b35b3ddf58071efece641b65de7d42024e5017697fda1fda6d',
    'src/http_client/native.rs': 'b7dc7ce75c2fd5084a8915153afe61825bf59531717a92af103257a98ecff317',
    'src/http_client/wasm.rs': '35f28273bfe897b8c1017a12862557c121427449e29bad7798512e77e3a0ccef',
    'src/latest_events/error.rs': '1695eddeae496322a9afc227d04728acefad0821fe3687537e318c2da9d256f6',
    'src/latest_events/mod.rs': 'caa0c1cdf505967d23f6f25c711a15c0fe5751c66a9d29fed714f34aa36710d0',
    'src/event_cache/caches/mod.rs': '489352b7e7effa110f261bfeef44b13fff9ba84668b0b0477283fc117a8e7205',
    'src/event_cache/caches/lock.rs': 'b447d2989017eda3bbee09da9931239dcbcf8d0109719775ead29e0da3cb54ee',
    'src/event_cache/caches/event_linked_chunk.rs': '0b91fa8a2650ea932491bfbd33b6f04ff2a9696fa435864ded4ddc6d0764900a',
    'src/event_cache/tasks.rs': '4cbfad0ef200b215054436bf6678869290f18b0cf6912da81b0eee9130fef6c7',
    'src/encryption/tasks.rs': '0417116f4bea9fdcbcfdc5eb3c505a15d55dbbee94051c3b5f2f1bfa6432637f',
    'src/encryption/backups/futures.rs': 'b6491b0acbd39cc8847f01a9ed524838153bf37d845bd0f68893ee694d90cec3',
    'src/encryption/backups/mod.rs': '1911420285ad5a872815bdb01316ed10123305ddf4c9801809f3149c1e3f884a',
    'src/encryption/backups/types.rs': 'ba4bbcfa916e9efc22fb95be8394c36c7101f18f1a7747c1c834e6db812ce6d6',
    'src/encryption/identities/devices.rs': '682f8470734b8c68627d6365393ead8ac50332ff183890be061ff0a13cf5acf5',
    'src/encryption/identities/mod.rs': '09270cd89db2265944223025629e66358de1683ee84f414d662d32f9be0146d3',
    'src/encryption/identities/users.rs': 'ba05b258d0c8e361a0d19c9d3f4ccbeb1e0952b45b62faa03b8bb124ce6a0370',
    'src/encryption/recovery/futures.rs': 'ddcef057f09ed6c1265625f5b25dc9dec06f4081534cabe4d3c7056e792ef58d',
    'src/encryption/recovery/mod.rs': '5835f5f9a6fab814245a31b6061140116fa85956de4fa7a6843b36ea9bd2cb61',
    'src/encryption/recovery/types.rs': '61f6c3b41655e1e4a05f8c4385423f92e3fca7109255046743808d274b563bf8',
    'src/encryption/futures.rs': '7a14802a8d1a327eb05d5b56849128f5858cd49f3be662081b84d4db13487efa',
    'src/encryption/secret_storage/futures.rs': '368a35e9695545deddef0a5d43ee3cebf390838b4b4df482848e47c83971ed13',
    'src/encryption/secret_storage/secret_store.rs': '5eadb0e6f28ce0e58edb4072d1c679778bf79dc85dd414faed6b7471d251482b',
    'src/encryption/verification/mod.rs': 'e5161ef91312920d382c047a4e1af54f3b1f337307da70ace10c40a4be5f5df6',
    'src/encryption/verification/qrcode.rs': '6713a4a0156e24e8522ebb3809a3b88b1ded740d0a097d591d620ec3f432d648',
    'src/encryption/verification/requests.rs': '066329c974739bcee8074c7fd9a7e3d7d94087777c72adc6bcdf3161c68c06da',
    'src/encryption/verification/sas.rs': 'f92ae21b896bfca3a3c911d3c097f5a8ada4956369e347c5168fb75b4d8584e1',
    'src/event_cache/automatic_pagination.rs': '3563a9dc3abc2cbb21cb35068c5ef9e83d7801bcbef6b6ef2b64d35241b7eb0d',
    'src/event_cache/deduplicator.rs': 'd0c5a164ff5dd57982f67960e0d6fcb964b6fbc1855b70af0b16e6109402d48f',
    'src/event_cache/mod.rs': '270685d940e2b504ad0f9500009b1614105e2008f841a9bd1219c2d97c247fe6',
    'src/event_cache/persistence.rs': 'c336c3bc3d9a3d87417d960d22d872f5913039ec820facccbae4ac9eeaf76eef',
    'src/event_cache/redecryptor.rs': '8a1d1e49224e836bfb3e653edc7b76d447549e707eb0c3591d349ed40a6d0d8c',
    'src/encryption/secret_storage/mod.rs': 'a56087751533a20da0e79e944cc2f6a1c74ceb46455bb56d3b5dba3d3ed29eec',
    'tests/integration/room/beacon_info/mod.rs': 'a0a3348d37066a6dfac9f449ba79056582555ad9b0ca75f91fcd98201cd4868c',
        },
        "postimage": {},
        "directories": {
    'changelog.d',
    'src',
    'src/authentication',
    'src/authentication/matrix',
    'src/authentication/oauth',
    'src/authentication/oauth/qrcode',
    'src/authentication/oauth/qrcode/rendezvous_channel',
    'src/authentication/oauth/qrcode/secure_channel',
    'src/client',
    'src/client/builder',
    'src/config',
    'src/docs',
    'src/encryption',
    'src/encryption/backups',
    'src/encryption/identities',
    'src/encryption/recovery',
    'src/encryption/secret_storage',
    'src/encryption/verification',
    'src/event_cache',
    'src/event_cache/caches',
    'src/event_cache/caches/event_focused',
    'src/event_cache/caches/pinned_events',
    'src/event_cache/caches/room',
    'src/event_cache/caches/thread',
    'src/event_handler',
    'src/http_client',
    'src/latest_events',
    'src/latest_events/latest_event',
    'src/notification_settings',
    'src/paginators',
    'src/room',
    'src/search_index',
    'src/send_queue',
    'src/sliding_sync',
    'src/sliding_sync/list',
    'src/test_utils',
    'src/test_utils/mocks',
    'src/utils',
    'src/widget',
    'src/widget/machine',
    'src/widget/machine/tests',
    'src/widget/settings',
    'src/widget/snapshots',
    'tests',
    'tests/integration',
    'tests/integration/encryption',
    'tests/integration/event_cache',
    'tests/integration/room',
    'tests/integration/room/attachment',
    'tests/integration/room/beacon',
    'tests/integration/room/beacon_info',
        },
    },
    CRYPTO: {
        "vendor": SRC / "vendor" / CRYPTO,
        "archive": Path("packaging/vendor-provenance/matrix-sdk-crypto-0.18.0.crate"),
        "archive_prefix": "matrix-sdk-crypto-0.18.0",
        "checksum": "c54afd2a326f51c13a6ad44ec86315a688fffeb3f1e287fb343e0e1836a3bdaf",
        "upstream": {
    '.cargo_vcs_info.json': '7205b8da9a5eee62d76da48b05a3230191e745bd2154fd931af2abe09e9cc768',
    '.cargo-ok': 'afbf9d0f3560b0fd7795e81c42a0a79ee6b6fc67e064f77826aee642cad28d91',
    'Cargo.lock': 'a5d7e872d3cbe3d1fdb5f2fb1aacf0647ad08774e939d19c4dd07103464686e9',
    'Cargo.toml': '98ce2b8539759300ebc3d29dec537801bd689473d51bb29b9570bcad335d565e',
    'Cargo.toml.orig': 'a55e288337569a13de7d9d76d66d79e49cf5961fe3027686cf74ea25c64e33eb',
    'changelog.d/.gitkeep': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'CHANGELOG.md': '4dee8d1608f5feed888adbb8252c65eae3357d791b55312d9ab162035b21a2a7',
    'README.md': '5979f1542caa62413d6b37a38917faf117deb39fab3a84bca935628f6bfe92ac',
    'src/backups/keys/backup.rs': '176ad05faf3571c0c338535faa8dec25f48b8b92da1216f395ce5759388358c2',
    'src/backups/keys/decryption.rs': '336c875f4b0d74d3ad89fe3ab73012bf630aba6344592f61bb2371c7fb14df36',
    'src/backups/keys/mod.rs': 'da18c9fbe68817b4aa6a7f8b928106056d75b5c787b9d4ba4273e7d43a916b73',
    'src/backups/mod.rs': '08d1c2058a9523bb36026b49cbee1331973ad1d014be673472aa19b97f643a9c',
    'src/ciphers.rs': '97796ab46a2e39ab830bf677e9023385d164098b59f58836693183e4cdae9923',
    'src/dehydrated_devices.rs': 'd26f416e169c0691dcf07f30e528ec42ce109862323c65256ae5a3214228b6f4',
    'src/error.rs': '4cf8df71b96fb97912dd3dee8f9c0bd83c0162543758afa31e5b064005508b1b',
    'src/file_encryption/attachments.rs': '4f7dcf9d9241e196eaba949fe6073d66dbdb25fb591dd254842f51a961102a43',
    'src/file_encryption/key_export.rs': '98283decacd5a67fdfb23d32b917327a81ed3f4c4c51c69b8e8c20940437e8c8',
    'src/file_encryption/mod.rs': 'e49502b3c6d5b422eda4380abcc7e71b7295505b43f47eb352ce503680345bd8',
    'src/gossiping/machine.rs': '2c05e6131da0bd4f444fe0256bf93d8805393dafa8f95dcd8ce6b6d8b62034f1',
    'src/gossiping/mod.rs': '19b6ff78dfd259bece954d3f408a8e1aaf25ef420a34883074202fa105d92b54',
    'src/identities/device.rs': '5ba8ea85fcac92d8e964e39462dd355ae64b25b62ea08ed4917c6134fe5de982',
    'src/identities/manager.rs': 'fe2e1bbaf3af0f8ebe830b5477502a161c765649dc2416964f9d1398df7ee8e4',
    'src/identities/mod.rs': 'e9053ecb75c71c38c4b379740be465e67aa8385a6c808a78c4a00215a0a1d4c6',
    'src/identities/room_identity_state.rs': '1b6148899beee74605cd26fb0cf55e792c42a90eaf4d4b501443dc237fe57316',
    'src/identities/user.rs': '3e4a2b3751efdd3d7db0399c23f8ac9248ccb651839195ed898d6d7bdb39edb2',
    'src/lib.rs': 'bcc6b433612812e05859d1edbac2ef7c3c6d172d476d8c4e74dd699159c10354',
    'src/machine/mod.rs': 'd2b37b4f4d9967f1572be7436a4f325939bf5087e05ec4d5eb9e29a8fa153083',
    'src/machine/test_helpers.rs': '79d3e4286fb84a66092e8a504e4c0e708f6c7f2f9510cef522070a5b0ef29e64',
    'src/machine/tests/decryption_verification_state.rs': 'efe61bc638377e461a52554af6d010d21225567667f4b8fd0f804a4ba2cfaa1c',
    'src/machine/tests/interactive_verification.rs': '264debda7ff59f9245f9198b704df6e604507b37db2e9656890a52c61bd013cd',
    'src/machine/tests/megolm_sender_data.rs': 'b17d877d116ae94dcd5cb3f1de24119b8c9ee74f069a7d8641452fb847476fab',
    'src/machine/tests/mod.rs': 'b4730e24e046584f99d889c369c0639c1a2382413024f64cb54d7fe16999340b',
    'src/machine/tests/olm_encryption.rs': '0445a5f53e3f061bad3ed556cbeca05008a98364d66159ff85c857e18a6a9650',
    'src/machine/tests/room_settings.rs': 'ed653ddf1553ca01f56ed5bd670921ec8a3e438db350dbc8694279f983f8b4b6',
    'src/machine/tests/send_encrypted_to_device.rs': 'a2ff33e5095a7f173b1bcc7083145ade72b0a7e598d21dc397a87079f80418a2',
    'src/machine/tests/snapshots/processed_to_device_variants-2.snap': '25e2665777734e0d5eaa48fb00c0b457eebe768c9c9a2f1c1d82b5fbb2f31466',
    'src/machine/tests/snapshots/processed_to_device_variants-3.snap': '39298d322ee950897ee2d1535df3d84870ffa250ab2b246a24dd9498c1fc1f85',
    'src/machine/tests/snapshots/processed_to_device_variants-4.snap': 'e19779fa1e1bdd67fbbd6cb1741ceb9eda8cbbd02443fe8dc9b7f2ae00b29144',
    'src/machine/tests/snapshots/processed_to_device_variants.snap': '166f7077d916932c71a296c3f903d5a3e7cd7a1b01b03727cc49d9e0c710bfcc',
    'src/olm/account.rs': 'd25bdf9331c9bad4f2d3b2e5f4e1e9c8fc23ccb58bb608cbc059369854a60419',
    'src/olm/group_sessions/forwarder_data.rs': 'e6878a5deee90615daa51b712a89d16d37fdcbab5053f6c8dd8486830e0b21b6',
    'src/olm/group_sessions/inbound.rs': '66b958e2409e7a6fabdea18a31aac588c12a0b9c8aa0d0d59a4edf193524dd2d',
    'src/olm/group_sessions/mod.rs': 'd18a69419f093c63248580c3844c7279e34a7074bcb8ea99445583b8f43db058',
    'src/olm/group_sessions/outbound.rs': '55ba667ef352f6a67d8114d908b26c9c6225f1aa0ee30a346d306bbe67496049',
    'src/olm/group_sessions/sender_data_finder.rs': '6661b19a7ee7ca10c4b15dc865d3792817386222f8e1070ee19bb298baeb81b2',
    'src/olm/group_sessions/sender_data.rs': '1190e0cfda01e13ec7aa1907ada34af5d8617ab76b2769f81ffdcc681ff461a0',
    'src/olm/group_sessions/snapshots/InboundGroupSession__test_pickle_snapshot__regression.snap': '0331ef018dfce7f74aa7eaccad93b438bc5d0a591d8dfe611c44d33c2f69cd58',
    'src/olm/group_sessions/snapshots/matrix_sdk_crypto__olm__group_sessions__sender_data__tests__snapshot_sender_data-2.snap': '3fb8722d57411c5e41b7043156fe15c98e1bfb10d3369bceadb64d4e1a0fda09',
    'src/olm/group_sessions/snapshots/matrix_sdk_crypto__olm__group_sessions__sender_data__tests__snapshot_sender_data-3.snap': '90f9158ac6e8805ad584a4907ed8f9f2e3e970570470341d1846befdeefb52bb',
    'src/olm/group_sessions/snapshots/matrix_sdk_crypto__olm__group_sessions__sender_data__tests__snapshot_sender_data-4.snap': '677ab14912f8a9c765ab5bb77cb628bae455ae0d4b7e92ca8b5d56adb5e2c2b5',
    'src/olm/group_sessions/snapshots/matrix_sdk_crypto__olm__group_sessions__sender_data__tests__snapshot_sender_data-5.snap': '8fa12528319abb06dfb60ed757508e4cb833b45734c057fae44612caed27a7f8',
    'src/olm/group_sessions/snapshots/matrix_sdk_crypto__olm__group_sessions__sender_data__tests__snapshot_sender_data-6.snap': '51fda8a818e9f1b056663850b00ca53ddbafb565f3e3622c1a0fdf68d5caeaa2',
    'src/olm/group_sessions/snapshots/matrix_sdk_crypto__olm__group_sessions__sender_data__tests__snapshot_sender_data.snap': 'df791dd0ea480e46d35ca802117f24cf85c0e3a356204973acd8d456f35f9120',
    'src/olm/group_sessions/snapshots/snapshot_forwarder_data-2.snap': '8f39c1e79c8e87e7a265b10063743dbf047adde0456eb067f4f5e9fbfdaf4ed0',
    'src/olm/group_sessions/snapshots/snapshot_forwarder_data.snap': '40a8abf8a5c2702d07c840841d92c3bf478714e60965b1594a339378735f26ba',
    'src/olm/mod.rs': 'e0efd71330ce87a0038a736145c60a5484e2d9dbcea53203b302572d151928d8',
    'src/olm/session.rs': 'a9fbba2523d319297e30471a3a87ba3a2446203fdc50beae99c308ed7763e781',
    'src/olm/signing/mod.rs': '7ec4a15e51665bdad0cd93885ebb5bc398cae15177f49175ae29206dc1635e44',
    'src/olm/signing/pk_signing.rs': '4cded1aa14c9f8c9653b40c7c6e4b6034f6c9f1a2fab4318fb5c3eab12df23a8',
    'src/olm/utility.rs': 'ac3fa0b45d4eea41db8ecfe98688d27a93e78dd3c99fbdb1c4dc1eda1a11c410',
    'src/secret_storage.rs': '49138c67c5010ef72c05117fa871fb60173cbe76f54bdf02c11caf40016f613d',
    'src/session_manager/group_sessions/mod.rs': '9acb919e4f19a6d4354f3faaa9eb8beadae7adcc0d4e2671922e69bfe4ceab7c',
    'src/session_manager/group_sessions/share_strategy.rs': '703319c779dd1f7d041eeb929710ee3191fb69d6c0ffa95e1a80e958ad64617f',
    'src/session_manager/group_sessions/snapshots/prepare_machine_with_dehydrated_device_of_verification_violation_user.snap': 'a26d642e2cbf88fbc8e88558c2e8a275d205483c23c7e611a4f292961423c3b8',
    'src/session_manager/group_sessions/snapshots/serialize_device_based_strategy.snap': '10167b1a46278919b580ff3cdcf206be3c4fec05de537328eeaefa0785fb20b4',
    'src/session_manager/group_sessions/snapshots/serialize_strategy_with_encrypted_state.snap': '8456fa64dbdd637c0dcb934fadb5ba4709b66eb78ec20d39c61d54bb1a0a702c',
    'src/session_manager/group_sessions/snapshots/should_not_share_with_unverified_dehydrated_device.snap': '5fcdc6df725288c28eb5e5ae8b519f2552cc2100e1747197adb917f9af924b39',
    'src/session_manager/group_sessions/snapshots/should_share_with_verified_dehydrated_device.snap': '24b3a64652ff110803af8e9f9e7415cc5ad7bfe9ed6f8d3c9cd60359416f27fc',
    'src/session_manager/group_sessions/snapshots/should_share_with_verified_device_of_pin_violation_user.snap': 'a26d642e2cbf88fbc8e88558c2e8a275d205483c23c7e611a4f292961423c3b8',
    'src/session_manager/mod.rs': 'd907e9cc3221e366157c14d378d92fa438ba0e76aaa418a8277bfd2427c3f5e0',
    'src/session_manager/sessions.rs': '64c9f755b1e4d53a80a3604bed50a194c1322b460da1f349ac871bf7729f156e',
    'src/snapshots/matrix_sdk_crypto__test__snapshot_decryption_settings.snap': '9d93bed310201eb6069d3c3a0bf53ed0f823813a0fa20562ba42d02e20fdfe75',
    'src/snapshots/matrix_sdk_crypto__test__snapshot_trust_requirement-2.snap': '410d4e55978060904c84b5edcb2b6d566630f2d7feb2031783f654beabdded75',
    'src/snapshots/matrix_sdk_crypto__test__snapshot_trust_requirement-3.snap': '310c3dea9da830572dcfe8d47bab4a4ae6bd6468c2cf7ffad532a737caf407ab',
    'src/snapshots/matrix_sdk_crypto__test__snapshot_trust_requirement.snap': 'cef6aebadbfd4e20e9e566d7843189b4bafd269cdfb012ebcc64cc8fc1b07386',
    'src/store/caches.rs': 'e641d961eca67dbcea4b9cc158e2deeeab18234306df409006846cf1e3872f03',
    'src/store/crypto_store_wrapper.rs': 'a54311ada30951b6dbc3f1654f5dc824336c5ad115da356984ecf87103b0504f',
    'src/store/error.rs': 'df90f1b74b30989c9809668290031507a6762ff6984e620c0aa3b7814cb2f6c0',
    'src/store/integration_tests.rs': '85aa9f393123d7f37036cca1126e9cc9d6cd0f1a54b8a789fde854dae270fcfa',
    'src/store/memorystore.rs': '30e38f42d26fe663118d93cebc7c79d60260d06aafabf8c5a93347c5612fd972',
    'src/store/mod.rs': '3e544daa00c3f343da36c47dca7f050fe4d707d748880550c9efa4bc6333b3e1',
    'src/store/snapshots/matrix_sdk_crypto__store__tests__build_room_key_bundle.snap': '809bd9144e3ddab3cb7854f14ee38e18a9862a4a9718fb727f7db4b334996c25',
    'src/store/traits.rs': '33d93b4fa508a8f4d06969bf271dbf7fa501de59da8d9cf6c0c4b23eda2a81c6',
    'src/store/types.rs': 'ffe59fce804eafb65c09966f49f458ce19c9f12bfaac0779fc5b017c49c31a7d',
    'src/types/backup.rs': '1e519f61dda715f8795f15b941703ce624303edc008b3cadcd5b182c721767b4',
    'src/types/cross_signing/common.rs': '89f73103297da8f5123eef30bd517887ed6de074dd7d39301abef469d069f7d9',
    'src/types/cross_signing/master.rs': 'f7d288bc30d3c89ad2ffadbe53ff4dad22a5a07a32d9a000976f2083e6864960',
    'src/types/cross_signing/mod.rs': '9b47c800789de21f03c15ec4afa252690ac79852bb401e14de2bdcb996e16600',
    'src/types/cross_signing/self_signing.rs': 'f288b535e15371c9f262661ab02d1793038d3e4e861e7bd887aabe97f66a3e70',
    'src/types/cross_signing/user_signing.rs': '6c3ecd631446e748f45f5477ff07e83506ecaea50dedff709b32660b4a7fbceb',
    'src/types/device_keys.rs': '3c7b73b97e346b717aa4e57a42d50b95bc5b23690e5853b1483d3c9b05fc6878',
    'src/types/events/dummy.rs': '60ebb620a48d3a16539c807820d42dbb8d951ccd95c9311240a428b2661def39',
    'src/types/events/forwarded_room_key.rs': 'c4aeb6535a6d8832c9c52c8530cc9ee97c71d71a02fa4b898233a37a030c0aef',
    'src/types/events/mod.rs': '380b5d901c83de1f58236ca01f074239eb1c7a846283ddbd9240bba09ecfc76e',
    'src/types/events/olm_v1.rs': '1d74edc03ae6649b4a37101239027c58cf900bd1ae44fb80cc13192241b557ca',
    'src/types/events/room_key_bundle.rs': '21439a76c6d1672f3c424ca8d455062f7d4acff04c067f0853cd9e0e4a129028',
    'src/types/events/room_key_request.rs': '5744d2ac1c1666420378208a847722f49b5832ec9fdc678882c9436a7a57bb84',
    'src/types/events/room_key_withheld.rs': '967c7e318b961e5a5d0619d2261e9549d9a642c6e0b7a0815e5cc0f0ff94a0c9',
    'src/types/events/room_key.rs': '443e6620384b17658ce204aebafc73b7a3a692eedb380bf97c1c90fb60a78c29',
    'src/types/events/room/encrypted.rs': '4982726ba174c3f9fd1d5bbd89cb575ee8add1bb756a7b04371b5ef3b587b2f6',
    'src/types/events/room/mod.rs': 'c0c08b652e9a5550673f1bf1c8c29145060bb4eda76976fac3a7224bec9c4930',
    'src/types/events/secret_push.rs': '215c4c550e574da99bfc682b9179f00c7d17629d45bfd230711ac0c1e03d4ec8',
    'src/types/events/secret_send.rs': 'b0218bf091da853f2aca6db39356649b1df2f2ef5c4383463ea46412b8a2753f',
    'src/types/events/snapshots/decrypted_to_device_event_snapshot.snap': 'f3fa443195a420122fa754f46a40bfdf4188ed9d89c0732fd68fc75d12ba31bb',
    'src/types/events/snapshots/sender_device_keys_are_deserialized.snap': '5a9e6de9666b1515700a6635a42a8d39731c3627838db58ac6425d38c3bc17a4',
    'src/types/events/to_device.rs': 'faf51b659c665b66ea845dd0697f3d0f48e21d38926d7e8d918e50031635e0af',
    'src/types/events/utd_cause.rs': '19a9f42d56ba16949d55c70ed9ed99ee5b8a5364bf4b97af6d21561e4c5390e7',
    'src/types/mod.rs': 'c7536236bd3a60b1fa60913c11eb62805da212dc270bdc03c5a8d135389b376f',
    'src/types/one_time_keys.rs': 'd5a3abe18d8aac6fe739a15e6ce9bd9867be74d2d3cabccc322f7dcd5b61c5f8',
    'src/types/qr_login/mod.rs': '56c36d540235e5eb3df369b5fa2a1a188e3fccbeabbb3df03b9855943c69b093',
    'src/types/qr_login/msc_4108.rs': '23264a2300622b0221d7d6ea01d1f415c398cdd21440bc2270e6302e6ef2f30f',
    'src/types/qr_login/msc_4388.rs': '7f5423d8036cd593a91128bb3e0162e69146882700936e32099a6666769dd066',
    'src/types/requests/enums.rs': '5c48c1e5cd6d3dba5aff05242ceeca647f6641d78d3ff581ea45178c508b4317',
    'src/types/requests/keys_backup.rs': 'fcfb5d3c85ba57e806fd44e95fd18a969b0dfb355c8079e61db97619d70505cc',
    'src/types/requests/keys_query.rs': 'ab35b906dc342b52cd315e0ee9528b82ce3b3c2ea053ce5f683f9343310a3938',
    'src/types/requests/mod.rs': '19807caa939f8ebecb2d1e4a3029b8e85c765b33f1d320e9cff4e5b77f496675',
    'src/types/requests/room_message.rs': 'b6feb2645238d2cc8e0fb481cd752916b845fa0054d06e484d5169cf4e03b7c5',
    'src/types/requests/signing_keys.rs': 'bfb43fa203ef5965eff279a93af038fe2185747eed6e0505f0d3456396ed08f0',
    'src/types/requests/to_device.rs': 'f6e232eb1a4905a1211f958d0d58e4ba7ad20e4e9dc8ac49245dd6f9654618eb',
    'src/types/requests/verification.rs': 'd15439572344e1bf8ef7a57bb1859404783b0cb06f133ca439636e7764f19883',
    'src/types/room_history.rs': 'c4ec6b3da6bb2b27dc84134e27aa560d34efac401fddd891811fa08eece0c60a',
    'src/types/snapshots/matrix_sdk_crypto__types__backup__tests__snapshot_room_key_backup_info-2.snap': '0672b144439cb85cb0641ea664c06b34d593bb3bb33f292cc5584cc0f9965df1',
    'src/types/snapshots/matrix_sdk_crypto__types__backup__tests__snapshot_room_key_backup_info.snap': '50fb5b74ae28aae24ffafd8c4cae466bf49659b47b8236daa48952a2a39b736d',
    'src/types/snapshots/matrix_sdk_crypto__types__room_history__tests__historic_room_key_debug.snap': 'ebe55ba84f8d67311e7bffdb9390764c3ac8a80692f79be979befad3ff8cb06e',
    'src/types/snapshots/matrix_sdk_crypto__types__test__snapshot_backup_decryption_key-2.snap': 'cef87ac7d071216c262eead113be04ca1bd2879269ec039c78bf3fd04c59cfbc',
    'src/types/snapshots/matrix_sdk_crypto__types__test__snapshot_backup_decryption_key.snap': '6e910d195fc797b72d7fa2ff165cf187991bde94217a43609172abf6e8ced8a6',
    'src/types/snapshots/matrix_sdk_crypto__types__test__snapshot_secret_bundle-2.snap': '20cd8951cfdd34071a4d1493cca002f7cb54e4ec6782b5cad248690912e375d8',
    'src/types/snapshots/matrix_sdk_crypto__types__test__snapshot_secret_bundle.snap': '8367eaa1602fe6b01208e9dc79ae7763f68be117e18d820f4bb07b32614b9ab1',
    'src/types/snapshots/matrix_sdk_crypto__types__test__snapshot_signatures.snap': '8c1aa5b4e364c8c63e8d2300e18b242c449b3df8255094b76761c54866a4a80b',
    'src/utilities.rs': 'f4729d202866cb7f36b3fcd58931a6294cd412b9290a1240db492c62626ea83a',
    'src/verification/cache.rs': 'f0df5abfeb2d1ddea891a6b01fcd14be19d40320a1d45c52ad58fc4959f60652',
    'src/verification/event_enums.rs': 'f33db34646f7e05b03a9447b0da1c88d79ce0d7f1941481753e0c9352c17e70d',
    'src/verification/machine.rs': '1f450750fc1a81ff92a1432d790aa5958fab95adea9b5fdaa2fa2f6190a7ce64',
    'src/verification/mod.rs': 'd92c0275eff050aa80abaf988d336488e8b09c57d7e20551cb2b80b88627f43a',
    'src/verification/qrcode.rs': '9bd3892729343a5f6950e929c2b2d370e3461f1b721cc82e2a2762a875ea81ba',
    'src/verification/requests.rs': 'e335024c663df8a2a7185728fd3ac30b6013e69b6a03e8ab4dc10d89575099af',
    'src/verification/sas/helpers.rs': 'ff4a996afc313135384114036af1179effb4f7802183355088fb7f51d7e46dfa',
    'src/verification/sas/inner_sas.rs': 'c359e1b963fde31508934e0f5c4526fe71620170e62afcbe03d274aa93483365',
    'src/verification/sas/mod.rs': '051fd5a261295ec1555fa0dbd5a1609e825e39c1e20381370b3034ad074ea1db',
    'src/verification/sas/sas_state.rs': 'f903ec02e13674430068cac0fa2c631bcf1267647ebbef1c52e9856c2e2fb0e6',
    'uniffi.toml': '1a294d0e48f8abf54169910c75166eaf8413da36cf9f9edc84bd28070d69d441',
        },
        "postimage": {},
        "directories": {
    'changelog.d',
    'src',
    'src/backups',
    'src/backups/keys',
    'src/file_encryption',
    'src/gossiping',
    'src/identities',
    'src/machine',
    'src/machine/tests',
    'src/machine/tests/snapshots',
    'src/olm',
    'src/olm/group_sessions',
    'src/olm/group_sessions/snapshots',
    'src/olm/signing',
    'src/session_manager',
    'src/session_manager/group_sessions',
    'src/session_manager/group_sessions/snapshots',
    'src/snapshots',
    'src/store',
    'src/store/snapshots',
    'src/types',
    'src/types/cross_signing',
    'src/types/events',
    'src/types/events/room',
    'src/types/events/snapshots',
    'src/types/qr_login',
    'src/types/requests',
    'src/types/snapshots',
    'src/verification',
    'src/verification/sas',
        },
    },
}
POSTIMAGE_DELTAS = {
    SDK: {
        "Cargo.toml": (PACKAGES[SDK]["upstream"]["Cargo.toml"], "bd77f06abe265570abd64bc9e73efa811bb1794801dcb1a2ed749df6a38e9044"),
        "Cargo.toml.orig": (PACKAGES[SDK]["upstream"]["Cargo.toml.orig"], "49813b0d20bec71f4482b841be22bee409e5b1587576b846705ba0b4cc75aab6"),
        "src/event_handler/mod.rs": (PACKAGES[SDK]["upstream"]["src/event_handler/mod.rs"], "1a1740f91accfde1daed879c96bb39836e86ff894013c509ba5e43518b8e5562"),
    },
    CRYPTO: {
        "src/machine/tests/send_encrypted_to_device.rs": ("a2ff33e5095a7f173b1bcc7083145ade72b0a7e598d21dc397a87079f80418a2", "7f27e20d67cca3e4d558cef1f9fd699c5422c160ebb05fb27f6ad11c5f167a94"),
        "src/session_manager/group_sessions/share_strategy.rs": ("703319c779dd1f7d041eeb929710ee3191fb69d6c0ffa95e1a80e958ad64617f", "9df5b2aaa95d91f5d19ddbfa04de7e3fd572127909d8f1980f8266626c4dd880"),
    },
}
# Keep the literal trust inventory single-sourced: the complete postimage is
# the archive inventory plus only these reviewed substitutions.
for _package_name, _deltas in POSTIMAGE_DELTAS.items():
    PACKAGES[_package_name]["postimage"] = {
        **PACKAGES[_package_name]["upstream"],
        **{path: postimage for path, (_, postimage) in _deltas.items()},
    }

class MatrixBackportProvenanceError(ValueError):
    """The Matrix candidate is not the exact reviewed postimage."""

def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def _load_toml(path: Path) -> dict[str, object]:
    try:
        result = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise MatrixBackportProvenanceError(f"cannot read TOML {path}: {error}") from error
    if not isinstance(result, dict):
        raise MatrixBackportProvenanceError(f"TOML {path} is not an object")
    return result

def _tree(root: Path) -> tuple[set[str], set[str]]:
    if not root.is_dir() or root.is_symlink():
        raise MatrixBackportProvenanceError(f"vendor root must be a real directory: {root}")
    files: set[str] = set(); directories: set[str] = set()
    for current, names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in names:
            path = current_path / name; relative = path.relative_to(root).as_posix()
            if path.is_symlink(): raise MatrixBackportProvenanceError(f"vendor symlink directory: {relative}")
            directories.add(relative)
        for name in file_names:
            path = current_path / name; relative = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file(): raise MatrixBackportProvenanceError(f"vendor non-regular file: {relative}")
            files.add(relative)
    return files, directories

def _archive_files(archive: Path, prefix: str) -> dict[str, str]:
    if not archive.is_file() or archive.is_symlink():
        raise MatrixBackportProvenanceError(f"official archive missing or non-regular: {archive}")
    found: dict[str, str] = {}
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                name = member.name
                if name.startswith("/") or ".." in Path(name).parts:
                    raise MatrixBackportProvenanceError(f"archive has unsafe member: {name!r}")
                if not name.startswith(prefix + "/"):
                    raise MatrixBackportProvenanceError(f"archive member outside package prefix: {name!r}")
                relative = name.removeprefix(prefix + "/")
                if not relative: continue
                if member.isdir(): continue
                if not member.isfile(): raise MatrixBackportProvenanceError(f"archive contains non-regular member: {relative!r}")
                if relative in found: raise MatrixBackportProvenanceError(f"archive duplicate member: {relative!r}")
                stream = bundle.extractfile(member)
                if stream is None: raise MatrixBackportProvenanceError(f"archive unreadable member: {relative!r}")
                digest = hashlib.sha256(stream.read()).hexdigest()
                found[relative] = digest
    except (OSError, tarfile.TarError) as error:
        raise MatrixBackportProvenanceError(f"cannot read official archive {archive}: {error}") from error
    return found

def _require_package_sources(root: Path, name: str) -> None:
    spec = PACKAGES[name]; archive = root / spec["archive"]
    if _sha256_path(archive) != spec["checksum"]:
        raise MatrixBackportProvenanceError(f"{name} archive checksum mismatch")
    upstream = spec["upstream"]
    if _archive_files(archive, spec["archive_prefix"]) != upstream:
        raise MatrixBackportProvenanceError(f"{name} archive member inventory mismatch")
    files, directories = _tree(root / spec["vendor"])
    if files != set(upstream) or directories != spec["directories"]:
        raise MatrixBackportProvenanceError(f"{name} vendor member allowlist mismatch")
    expected = dict(upstream); expected.update(spec["postimage"])
    for path, digest in expected.items():
        if _sha256_path(root / spec["vendor"] / path) != digest:
            raise MatrixBackportProvenanceError(f"{name} vendor postimage mismatch: {path}")
    deltas = POSTIMAGE_DELTAS[name]
    if set(deltas) != {path for path in upstream if upstream[path] != spec["postimage"][path]}:
        raise MatrixBackportProvenanceError(f"{name} postimage allowlist is incomplete")
    for path, (preimage, postimage) in deltas.items():
        if upstream.get(path) != preimage or spec["postimage"].get(path) != postimage:
            raise MatrixBackportProvenanceError(f"{name} postimage declaration mismatch: {path}")
    manifest = _load_toml(root / spec["vendor"] / "Cargo.toml").get("package")
    if not isinstance(manifest, dict) or (manifest.get("name"), manifest.get("version")) != (name, VERSION):
        raise MatrixBackportProvenanceError(f"{name} manifest identity mismatch")

def validate_sources(root: Path = ROOT) -> None:
    """Authenticate both archives and their exact vendor postimages before Cargo."""
    root = root.resolve()
    for name in (SDK, CRYPTO): _require_package_sources(root, name)

def _require_patch_and_lock(root: Path) -> None:
    workspace = _load_toml(root / MANIFEST_RELATIVE); patch = workspace.get("patch")
    crates = patch.get("crates-io") if isinstance(patch, dict) else None
    if not isinstance(crates, dict): raise MatrixBackportProvenanceError("workspace has no crates-io patch table")
    for name in (SDK, CRYPTO):
        if crates.get(name) != {"path": f"vendor/{name}", "version": f"={VERSION}"}:
            raise MatrixBackportProvenanceError(f"{name} path/version patch mismatch")
    packages = _load_toml(root / LOCK_RELATIVE).get("package")
    if not isinstance(packages, list): raise MatrixBackportProvenanceError("workspace lock has no package list")
    for name in (SDK, CRYPTO):
        matches = [p for p in packages if isinstance(p, dict) and p.get("name") == name]
        if len(matches) != 1 or matches[0].get("version") != VERSION or "source" in matches[0] or "checksum" in matches[0]:
            raise MatrixBackportProvenanceError(f"workspace must contain one source-less {name}@{VERSION}")
    if any(isinstance(p, dict) and p.get("name") == "anymap2" for p in packages):
        raise MatrixBackportProvenanceError("workspace must not resolve anymap2")
    anymap3 = [p for p in packages if isinstance(p, dict) and p.get("name") == "anymap3"]
    if len(anymap3) != 1 or (anymap3[0].get("version"), anymap3[0].get("source"), anymap3[0].get("checksum")) != ("1.1.0", REGISTRY_SOURCE, ANYMAP3_CHECKSUM):
        raise MatrixBackportProvenanceError("workspace must contain one canonical anymap3@1.1.0")

def _require_0318_exception(root: Path, today: date) -> None:
    if today >= EXPIRY_DATE: raise MatrixBackportProvenanceError(f"{ADVISORY} exception expired on {EXPIRY_DATE.isoformat()}")
    audit = _load_toml(root / AUDIT_RELATIVE).get("advisories")
    deny = _load_toml(root / DENY_RELATIVE).get("advisories")
    audit_ignore = audit.get("ignore") if isinstance(audit, dict) else None
    deny_ignore = deny.get("ignore") if isinstance(deny, dict) else None
    if not isinstance(audit_ignore, list) or Counter(x for x in audit_ignore if x == ADVISORY) != Counter({ADVISORY: 1}):
        raise MatrixBackportProvenanceError(f"{ADVISORY} must occur exactly once in audit.toml")
    ids = [entry.get("id") for entry in deny_ignore if isinstance(entry, dict)] if isinstance(deny_ignore, list) else []
    if Counter(x for x in ids if x == ADVISORY) != Counter({ADVISORY: 1}):
        raise MatrixBackportProvenanceError(f"{ADVISORY} must occur exactly once in deny.toml")

def validate(root: Path = ROOT, *, today: date | None = None) -> None:
    """Final acceptance: source custody, final workspace graph, and synchronized exception."""
    root = root.resolve(); validate_sources(root); _require_patch_and_lock(root)
    _require_0318_exception(root, datetime.now(timezone.utc).date() if today is None else today)

def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__); result.add_argument("--root", type=Path, default=ROOT)
    result.add_argument("--source-only", action="store_true", help="pre-Cargo source custody only; never final acceptance")
    return result

def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.source_only: validate_sources(args.root)
        else: validate(args.root)
    except MatrixBackportProvenanceError as error:
        print(f"::error::matrix provenance gate failed: {error}", file=sys.stderr); return 1
    print("matrix provenance gate passed (source-only)" if args.source_only else "matrix provenance gate passed (final)")
    return 0
if __name__ == "__main__": raise SystemExit(main())
