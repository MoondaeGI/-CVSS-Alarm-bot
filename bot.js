// bot.js
import "dotenv/config";
import { Client, GatewayIntentBits, EmbedBuilder } from "discord.js";
import fetch from "node-fetch";
import { XMLParser } from "fast-xml-parser";
import fs from "node:fs";

const { DISCORD_TOKEN, DISCORD_CHANNEL_ID } = process.env;

const CVE_FEED_URL = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml";
const STATE_FILE = "./seen_cve.json";

let seen = new Set();

// 이전 상태 로드
function loadSeen() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const data = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
      if (Array.isArray(data)) seen = new Set(data);
    }
  } catch (e) {
    console.error("seen 로드 실패:", e);
  }
}

// 상태 저장
function saveSeen() {
  fs.writeFileSync(STATE_FILE, JSON.stringify([...seen], null, 2), "utf8");
}

// RSS → 최근 CVE n개 가져오기
async function fetchCVE(limit = 30) {
  const res = await fetch(CVE_FEED_URL);
  const xml = await res.text();
  const parser = new XMLParser();
  const parsed = parser.parse(xml);

  const items = parsed?.rss?.channel?.item || [];
  return items.slice(0, limit).map((i) => ({
    id: i.link, // RSS에서 link는 유일값
    title: i.title,
    link: i.link,
    pubDate: i.pubDate,
  }));
}

// 새 CVE 감지해서 보내기
async function watchCVE(client) {
  const channel = await client.channels.fetch(DISCORD_CHANNEL_ID);
  if (!channel) return console.error("채널 없음");

  try {
    const items = await fetchCVE(50);
    const newOnes = items.filter((i) => !seen.has(i.id));

    if (newOnes.length === 0) return; // 새 항목 없음

    console.log(`새 CVE ${newOnes.length}개 발견 → 푸시`);

    for (const item of newOnes.reverse()) {
      seen.add(item.id);

      const embed = new EmbedBuilder()
        .setTitle(`🧨 새 CVE 감지: ${item.title.split(" ")[0]}`)
        .setDescription(item.title)
        .setURL(item.link)
        .addFields({ name: "발표일", value: item.pubDate || "없음" })
        .setColor(0xff0000)
        .setTimestamp(new Date());

      await channel.send({ embeds: [embed] });
    }

    saveSeen();
  } catch (e) {
    console.error("CVE 감시 오류:", e);
  }
}

const client = new Client({
  intents: [GatewayIntentBits.Guilds],
});

client.once("ready", async () => {
  console.log(`로그인 완료: ${client.user.tag}`);

  loadSeen();

  // 최초 실행 시 기존 항목은 푸시하지 않고 seen 처리만
  const init = await fetchCVE(50);
  if (seen.size === 0) {
    init.forEach((i) => seen.add(i.id));
    saveSeen();
    console.log("최초 실행 → 기존 50개는 seen 처리만 함");
  }

  // 5분마다 자동 pull
  setInterval(() => watchCVE(client), 5 * 60 * 1000);
  console.log("자동 CVE 감시 시작 (5분 간격)");
});

client.login(DISCORD_TOKEN);
