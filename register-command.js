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
    .setDescription("NVD CVE API 쿼리 문자열로 검색합니다.")
    .addStringOption((option) =>
      option
        .setName("query")
        .setDescription(
          "NVD API 뒤에 붙일 쿼리 (예: keywordSearch=chrome&resultsPerPage=5)"
        )
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
