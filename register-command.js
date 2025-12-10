// register-commands.js
import "dotenv/config";
import { REST, Routes, SlashCommandBuilder } from "discord.js";

const { DISCORD_TOKEN, DISCORD_CLIENT_ID, DISCORD_GUILD_ID } = process.env;

if (!DISCORD_TOKEN || !DISCORD_CLIENT_ID || !DISCORD_GUILD_ID) {
  console.error("DISCORD_TOKEN / DISCORD_CLIENT_ID / DISCORD_GUILD_ID 필요");
  process.exit(1);
}

const commands = [
  new SlashCommandBuilder()
    .setName("cve-search")
    .setDescription("자연어로 CVE 검색 (예: '최근 1년 critical 윈도우 취약점')")
    .addStringOption((option) =>
      option
        .setName("question")
        .setDescription("검색하고 싶은 내용을 자연어로 적어주세요.")
        .setRequired(true)
    )
    .toJSON(),
];

const rest = new REST({ version: "10" }).setToken(DISCORD_TOKEN);

async function main() {
  try {
    console.log("슬래시 커맨드 등록 중...");
    await rest.put(
      Routes.applicationGuildCommands(DISCORD_CLIENT_ID, DISCORD_GUILD_ID),
      { body: commands }
    );
    console.log("슬래시 커맨드 등록 완료!");
  } catch (e) {
    console.error(e);
  }
}

main();
