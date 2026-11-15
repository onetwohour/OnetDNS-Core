//! Blocking rules per service. Choosing one service blocks every domain it uses. The rules are
//! built in rather than fetched from a list URL.

pub struct Service {
    /// The name written in config.
    pub id: &'static str,
    pub name: &'static str,
    pub group: &'static str,
    pub rules: &'static [&'static str],
}

pub const SERVICES: &[Service] = &[
    Service {
        id: "4chan",
        name: "4chan",
        group: "social_network",
        rules: &["||4chan.org^", "||4channel.org^", "||4cdn.org^"],
    },
    Service {
        id: "9gag",
        name: "9GAG",
        group: "social_network",
        rules: &["||9gag.com^", "||9cache.com^"],
    },
    Service {
        id: "facebook",
        name: "Facebook",
        group: "social_network",
        rules: &[
            "||facebook.com^",
            "||fb.com^",
            "||fbcdn.net^",
            "||facebook.net^",
            "||fbsbx.com^",
        ],
    },
    Service {
        id: "instagram",
        name: "Instagram",
        group: "social_network",
        rules: &["||instagram.com^", "||cdninstagram.com^", "||ig.me^"],
    },
    Service {
        id: "twitter",
        name: "X (Twitter)",
        group: "social_network",
        rules: &["||x.com^", "||twitter.com^", "||t.co^", "||twimg.com^"],
    },
    Service {
        id: "tiktok",
        name: "TikTok",
        group: "social_network",
        rules: &[
            "||tiktok.com^",
            "||tiktokcdn.com^",
            "||tiktokv.com^",
            "||musical.ly^",
            "||byteoversea.com^",
        ],
    },
    Service {
        id: "reddit",
        name: "Reddit",
        group: "social_network",
        rules: &[
            "||reddit.com^",
            "||redd.it^",
            "||redditstatic.com^",
            "||redditmedia.com^",
        ],
    },
    Service {
        id: "snapchat",
        name: "Snapchat",
        group: "social_network",
        rules: &["||snapchat.com^", "||snap.com^", "||sc-cdn.net^"],
    },
    Service {
        id: "pinterest",
        name: "Pinterest",
        group: "social_network",
        rules: &["||pinterest.com^", "||pinimg.com^"],
    },
    Service {
        id: "linkedin",
        name: "LinkedIn",
        group: "social_network",
        rules: &["||linkedin.com^", "||licdn.com^"],
    },
    Service {
        id: "tumblr",
        name: "Tumblr",
        group: "social_network",
        rules: &["||tumblr.com^", "||tumblr.co^", "||tmblr.co^"],
    },
    Service {
        id: "threads",
        name: "Threads",
        group: "social_network",
        rules: &["||threads.net^"],
    },
    Service {
        id: "mastodon",
        name: "Mastodon",
        group: "social_network",
        rules: &["||joinmastodon.org^", "||mastodon.social^"],
    },
    Service {
        id: "vk",
        name: "VK",
        group: "social_network",
        rules: &["||vk.com^", "||vk.me^", "||userapi.com^"],
    },
    Service {
        id: "weibo",
        name: "Weibo",
        group: "social_network",
        rules: &["||weibo.com^", "||weibo.cn^", "||sinaimg.cn^"],
    },
    Service {
        id: "whatsapp",
        name: "WhatsApp",
        group: "messenger",
        rules: &["||whatsapp.com^", "||whatsapp.net^"],
    },
    Service {
        id: "telegram",
        name: "Telegram",
        group: "messenger",
        rules: &[
            "||telegram.org^",
            "||telegram.me^",
            "||t.me^",
            "||tdesktop.com^",
        ],
    },
    Service {
        id: "discord",
        name: "Discord",
        group: "messenger",
        rules: &[
            "||discord.com^",
            "||discord.gg^",
            "||discordapp.com^",
            "||discordapp.net^",
        ],
    },
    Service {
        id: "signal",
        name: "Signal",
        group: "messenger",
        rules: &["||signal.org^", "||signal.art^"],
    },
    Service {
        id: "line",
        name: "LINE",
        group: "messenger",
        rules: &["||line.me^", "||line-apps.com^", "||line-scdn.net^"],
    },
    Service {
        id: "viber",
        name: "Viber",
        group: "messenger",
        rules: &["||viber.com^", "||viber.co.jp^"],
    },
    Service {
        id: "wechat",
        name: "WeChat",
        group: "messenger",
        rules: &["||wechat.com^", "||weixin.qq.com^", "||weixin.com^"],
    },
    Service {
        id: "kakao",
        name: "KakaoTalk",
        group: "messenger",
        rules: &["||kakao.com^", "||kakaocdn.net^", "||kakaocorp.com^"],
    },
    Service {
        id: "messenger",
        name: "Messenger",
        group: "messenger",
        rules: &["||messenger.com^", "||m.me^"],
    },
    Service {
        id: "slack",
        name: "Slack",
        group: "messenger",
        rules: &["||slack.com^", "||slack-edge.com^", "||slack-msgs.com^"],
    },
    Service {
        id: "teams",
        name: "Microsoft Teams",
        group: "messenger",
        rules: &[
            "||teams.microsoft.com^",
            "||teams.live.com^",
            "||skype.com^",
        ],
    },
    Service {
        id: "youtube",
        name: "YouTube",
        group: "streaming",
        rules: &[
            "||youtube.com^",
            "||youtu.be^",
            "||ytimg.com^",
            "||googlevideo.com^",
            "||youtube-nocookie.com^",
        ],
    },
    Service {
        id: "netflix",
        name: "Netflix",
        group: "streaming",
        rules: &[
            "||netflix.com^",
            "||nflxvideo.net^",
            "||nflximg.net^",
            "||nflxext.com^",
            "||nflxso.net^",
        ],
    },
    Service {
        id: "twitch",
        name: "Twitch",
        group: "streaming",
        rules: &["||twitch.tv^", "||ttvnw.net^", "||jtvnw.net^"],
    },
    Service {
        id: "disneyplus",
        name: "Disney+",
        group: "streaming",
        rules: &[
            "||disneyplus.com^",
            "||disney-plus.net^",
            "||dssott.com^",
            "||bamgrid.com^",
        ],
    },
    Service {
        id: "hulu",
        name: "Hulu",
        group: "streaming",
        rules: &["||hulu.com^", "||huluim.com^"],
    },
    Service {
        id: "max",
        name: "Max",
        group: "streaming",
        rules: &["||max.com^", "||hbomax.com^", "||hbonow.com^"],
    },
    Service {
        id: "prime_video",
        name: "Prime Video",
        group: "streaming",
        rules: &["||primevideo.com^", "||amazonvideo.com^", "||aiv-cdn.net^"],
    },
    Service {
        id: "spotify",
        name: "Spotify",
        group: "streaming",
        rules: &["||spotify.com^", "||scdn.co^", "||spotifycdn.com^"],
    },
    Service {
        id: "apple_music",
        name: "Apple Music",
        group: "streaming",
        rules: &["||music.apple.com^", "||mzstatic.com^"],
    },
    Service {
        id: "soundcloud",
        name: "SoundCloud",
        group: "streaming",
        rules: &["||soundcloud.com^", "||sndcdn.com^"],
    },
    Service {
        id: "vimeo",
        name: "Vimeo",
        group: "streaming",
        rules: &["||vimeo.com^", "||vimeocdn.com^"],
    },
    Service {
        id: "dailymotion",
        name: "Dailymotion",
        group: "streaming",
        rules: &["||dailymotion.com^", "||dmcdn.net^"],
    },
    Service {
        id: "crunchyroll",
        name: "Crunchyroll",
        group: "streaming",
        rules: &["||crunchyroll.com^", "||vrv.co^"],
    },
    Service {
        id: "paramountplus",
        name: "Paramount+",
        group: "streaming",
        rules: &["||paramountplus.com^", "||cbsivideo.com^"],
    },
    Service {
        id: "peacock",
        name: "Peacock",
        group: "streaming",
        rules: &["||peacocktv.com^", "||peacock.com^"],
    },
    Service {
        id: "steam",
        name: "Steam",
        group: "gaming",
        rules: &[
            "||steampowered.com^",
            "||steamcommunity.com^",
            "||steamstatic.com^",
            "||steamcontent.com^",
        ],
    },
    Service {
        id: "epic_games",
        name: "Epic Games",
        group: "gaming",
        rules: &[
            "||epicgames.com^",
            "||epicgames.dev^",
            "||unrealengine.com^",
        ],
    },
    Service {
        id: "playstation",
        name: "PlayStation",
        group: "gaming",
        rules: &[
            "||playstation.com^",
            "||playstation.net^",
            "||sonyentertainmentnetwork.com^",
        ],
    },
    Service {
        id: "xbox",
        name: "Xbox",
        group: "gaming",
        rules: &["||xbox.com^", "||xboxlive.com^", "||xboxservices.com^"],
    },
    Service {
        id: "nintendo",
        name: "Nintendo",
        group: "gaming",
        rules: &["||nintendo.com^", "||nintendo.net^", "||nintendo.co.jp^"],
    },
    Service {
        id: "roblox",
        name: "Roblox",
        group: "gaming",
        rules: &["||roblox.com^", "||rbxcdn.com^"],
    },
    Service {
        id: "minecraft",
        name: "Minecraft",
        group: "gaming",
        rules: &["||minecraft.net^", "||mojang.com^"],
    },
    Service {
        id: "riot_games",
        name: "Riot Games",
        group: "gaming",
        rules: &[
            "||riotgames.com^",
            "||leagueoflegends.com^",
            "||valorant.com^",
            "||pvp.net^",
        ],
    },
    Service {
        id: "battle_net",
        name: "Battle.net",
        group: "gaming",
        rules: &["||battle.net^", "||blizzard.com^", "||blizzard.net^"],
    },
    Service {
        id: "ea",
        name: "Electronic Arts",
        group: "gaming",
        rules: &["||ea.com^", "||origin.com^", "||easports.com^"],
    },
    Service {
        id: "ubisoft",
        name: "Ubisoft",
        group: "gaming",
        rules: &["||ubisoft.com^", "||ubi.com^", "||ubisoftconnect.com^"],
    },
    Service {
        id: "geforce_now",
        name: "GeForce NOW",
        group: "gaming",
        rules: &["||geforcenow.com^", "||nvidia.com^"],
    },
    Service {
        id: "amazon",
        name: "Amazon",
        group: "shopping",
        rules: &[
            "||amazon.com^",
            "||amazon.co.kr^",
            "||amazon.co.jp^",
            "||media-amazon.com^",
            "||ssl-images-amazon.com^",
        ],
    },
    Service {
        id: "aliexpress",
        name: "AliExpress",
        group: "shopping",
        rules: &["||aliexpress.com^", "||aliexpress.ru^"],
    },
    Service {
        id: "ebay",
        name: "eBay",
        group: "shopping",
        rules: &["||ebay.com^", "||ebaystatic.com^", "||ebayimg.com^"],
    },
    Service {
        id: "temu",
        name: "Temu",
        group: "shopping",
        rules: &["||temu.com^", "||kwcdn.com^"],
    },
    Service {
        id: "shein",
        name: "SHEIN",
        group: "shopping",
        rules: &["||shein.com^", "||sheincdn.com^"],
    },
    Service {
        id: "coupang",
        name: "Coupang",
        group: "shopping",
        rules: &["||coupang.com^", "||coupangcdn.com^"],
    },
    Service {
        id: "naver_shopping",
        name: "Naver Shopping",
        group: "shopping",
        rules: &["||shopping.naver.com^", "||shoppinglive.naver.com^"],
    },
    Service {
        id: "walmart",
        name: "Walmart",
        group: "shopping",
        rules: &["||walmart.com^", "||walmartimages.com^"],
    },
    Service {
        id: "etsy",
        name: "Etsy",
        group: "shopping",
        rules: &["||etsy.com^", "||etsystatic.com^"],
    },
    Service {
        id: "chatgpt",
        name: "ChatGPT",
        group: "ai",
        rules: &[
            "||chatgpt.com^",
            "||openai.com^",
            "||oaistatic.com^",
            "||oaiusercontent.com^",
        ],
    },
    Service {
        id: "claude",
        name: "Claude",
        group: "ai",
        rules: &["||claude.ai^", "||anthropic.com^"],
    },
    Service {
        id: "gemini",
        name: "Google Gemini",
        group: "ai",
        rules: &["||gemini.google.com^", "||bard.google.com^"],
    },
    Service {
        id: "copilot",
        name: "Microsoft Copilot",
        group: "ai",
        rules: &["||copilot.microsoft.com^", "||copilot.cloud.microsoft^"],
    },
    Service {
        id: "perplexity",
        name: "Perplexity",
        group: "ai",
        rules: &["||perplexity.ai^"],
    },
    Service {
        id: "deepseek",
        name: "DeepSeek",
        group: "ai",
        rules: &["||deepseek.com^"],
    },
    Service {
        id: "grok",
        name: "Grok",
        group: "ai",
        rules: &["||grok.com^", "||x.ai^"],
    },
    Service {
        id: "midjourney",
        name: "Midjourney",
        group: "ai",
        rules: &["||midjourney.com^", "||cdn.midjourney.com^"],
    },
    Service {
        id: "character_ai",
        name: "Character.AI",
        group: "ai",
        rules: &["||character.ai^", "||characterai.io^"],
    },
    Service {
        id: "tinder",
        name: "Tinder",
        group: "dating",
        rules: &["||tinder.com^", "||gotinder.com^"],
    },
    Service {
        id: "bumble",
        name: "Bumble",
        group: "dating",
        rules: &["||bumble.com^", "||bumbleapp.com^"],
    },
    Service {
        id: "hinge",
        name: "Hinge",
        group: "dating",
        rules: &["||hinge.co^"],
    },
    Service {
        id: "okcupid",
        name: "OkCupid",
        group: "dating",
        rules: &["||okcupid.com^"],
    },
    Service {
        id: "match",
        name: "Match",
        group: "dating",
        rules: &["||match.com^"],
    },
    Service {
        id: "grindr",
        name: "Grindr",
        group: "dating",
        rules: &["||grindr.com^"],
    },
    Service {
        id: "bet365",
        name: "bet365",
        group: "gambling",
        rules: &["||bet365.com^", "||bet365.bet^"],
    },
    Service {
        id: "pokerstars",
        name: "PokerStars",
        group: "gambling",
        rules: &["||pokerstars.com^", "||pokerstarscasino.com^"],
    },
    Service {
        id: "draftkings",
        name: "DraftKings",
        group: "gambling",
        rules: &["||draftkings.com^"],
    },
    Service {
        id: "fanduel",
        name: "FanDuel",
        group: "gambling",
        rules: &["||fanduel.com^"],
    },
    Service {
        id: "github",
        name: "GitHub",
        group: "software",
        rules: &[
            "||github.com^",
            "||githubusercontent.com^",
            "||githubassets.com^",
        ],
    },
    Service {
        id: "gitlab",
        name: "GitLab",
        group: "software",
        rules: &["||gitlab.com^", "||gitlab-static.net^"],
    },
    Service {
        id: "dropbox",
        name: "Dropbox",
        group: "software",
        rules: &[
            "||dropbox.com^",
            "||dropboxapi.com^",
            "||dropboxstatic.com^",
        ],
    },
    Service {
        id: "google_drive",
        name: "Google Drive",
        group: "software",
        rules: &["||drive.google.com^", "||docs.google.com^"],
    },
    Service {
        id: "icloud",
        name: "iCloud",
        group: "software",
        rules: &["||icloud.com^", "||icloud-content.com^"],
    },
    Service {
        id: "onedrive",
        name: "OneDrive",
        group: "software",
        rules: &["||onedrive.com^", "||1drv.com^", "||sharepoint.com^"],
    },
    Service {
        id: "adobe",
        name: "Adobe",
        group: "software",
        rules: &["||adobe.com^", "||adobelogin.com^", "||adobecc.com^"],
    },
    Service {
        id: "zoom",
        name: "Zoom",
        group: "software",
        rules: &["||zoom.us^", "||zoom.com^", "||zoomcdn.com^"],
    },
    Service {
        id: "cloudflare",
        name: "Cloudflare",
        group: "hosting",
        rules: &[
            "||cloudflare.com^",
            "||cloudflare.net^",
            "||cloudflare-dns.com^",
        ],
    },
    Service {
        id: "aws",
        name: "Amazon Web Services",
        group: "hosting",
        rules: &["||aws.amazon.com^", "||amazonaws.com^", "||cloudfront.net^"],
    },
    Service {
        id: "azure",
        name: "Microsoft Azure",
        group: "hosting",
        rules: &[
            "||azure.com^",
            "||azurewebsites.net^",
            "||windowsazure.com^",
        ],
    },
    Service {
        id: "google_cloud",
        name: "Google Cloud",
        group: "hosting",
        rules: &["||cloud.google.com^", "||googleapis.com^", "||appspot.com^"],
    },
];

pub fn service_rules(id: &str) -> Option<&'static [&'static str]> {
    SERVICES
        .iter()
        .find(|service| service.id.eq_ignore_ascii_case(id))
        .map(|service| service.rules)
}

pub fn list() -> Vec<(&'static str, &'static str)> {
    SERVICES
        .iter()
        .map(|service| (service.id, service.name))
        .collect()
}

pub fn catalog() -> &'static [Service] {
    SERVICES
}
