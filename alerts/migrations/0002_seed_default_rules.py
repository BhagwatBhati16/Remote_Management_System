from django.db import migrations


_PROCESS_NAMES = [
    # Launchers
    "steam", "steamwebhelper", "EpicGamesLauncher", "Battle.net", "Origin",
    "GalaxyClient", "UbisoftConnect", "bethesda.net_launcher",
    # Popular games
    "VALORANT", "VALORANT-Win64-Shipping", "csgo", "cs2",
    "GTA5", "GTA5.exe", "FiveM", "Minecraft", "javaw",
    "FortniteClient-Win64-Shipping", "RocketLeague",
    "Roblox", "RobloxPlayerBeta", "RobloxPlayerLauncher",
    "LeagueOfLegends", "League of Legends",
    "PUBG", "TslGame", "Overwatch", "Dota2",
    "r5apex",  # Apex Legends
    "NMS",  # No Man's Sky
    "RainbowSix", "RainbowSix_BE",
    "eldenring", "sekiro",
    "Warframe", "Warframe.x64",
    "destiny2",
    "Among Us",
]

_WINDOW_KEYWORDS = [
    "friv", "poki", "miniclip", "Y8.com", "y8.com",
    "crazygames", "coolmathgames", "cool math games",
    "krunker", "1v1.lol", "shellshock",
    "slither.io", "slither", "agar.io", "diep.io",
    "zombs.io", "surviv.io", "skribbl.io",
    "papas games", "unblocked games",
    "io games", "play free games",
    "armor games", "kongregate",
    "newgrounds", "addicting games",
]

_WEBSITE_DOMAINS = [
    "friv.com", "poki.com", "miniclip.com", "y8.com",
    "crazygames.com", "coolmathgames.com",
    "krunker.io", "1v1.lol", "shellshock.io",
    "slither.io", "agar.io", "diep.io",
    "zombs.io", "surviv.io", "skribbl.io",
    "armorgames.com", "kongregate.com",
    "newgrounds.com", "addictinggames.com",
    "iogames.space", "games.crazygames.com",
    "now.gg", "bluestacks.com",
    "steamcommunity.com", "store.steampowered.com",
]


def seed_rules(apps, schema_editor):
    AlertRule = apps.get_model("alerts", "AlertRule")
    for name in _PROCESS_NAMES:
        AlertRule.objects.get_or_create(rule_type="process_name", value=name, defaults={"is_active": True})
    for kw in _WINDOW_KEYWORDS:
        AlertRule.objects.get_or_create(rule_type="window_keyword", value=kw, defaults={"is_active": True})
    for dom in _WEBSITE_DOMAINS:
        AlertRule.objects.get_or_create(rule_type="website_domain", value=dom, defaults={"is_active": True})


def remove_rules(apps, schema_editor):
    AlertRule = apps.get_model("alerts", "AlertRule")
    AlertRule.objects.filter(
        value__in=_PROCESS_NAMES + _WINDOW_KEYWORDS + _WEBSITE_DOMAINS
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("alerts", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_rules, remove_rules),
    ]
