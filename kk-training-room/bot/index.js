const {
  Client,
  GatewayIntentBits,
  Events,
  EmbedBuilder,
  MessageFlags,
} = require('discord.js');

/* ───────────────────── CONFIG ───────────────────── */

const CONFIG = {
  ROLE_NAME: 'K&K',
  ADMIN_NAME: 'admin',
  WEBHOOK_NAME: 'K&K Announcer',
  TARGET_GUILD_ID: '1455821434927579198',
};

/* ───────────────────── CLIENT ───────────────────── */

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
});

/* ───────────────────── DATA ───────────────────── */

const HAN_SHANGYAN_QUOTES = [
  "I'm yours. Sooner or later, I will be.",
  "Except for you, no one else matters to me.",
  "Romance isn't important. A lifetime is. I'll give you all of it.",
  "My little squid, I'll take responsibility for you.",
  "I don't know how to talk sweetly, but everything I do is for you.",
  "To you, I might just be one relationship. To me, you are my life.",
  "As long as you're willing to stay, I won't let go.",
  "I don't like explaining myself, but for you, I will.",
  "Winning is important, but you matter more.",
  "I'm not good at promises. If I say it, I mean it.",
  "I don't need the world to understand me. You understanding me is enough.",
  "I won't say I love you often, but I'll prove it every day.",
  "I've waited a long time. I can wait for you too.",
  "If you want me, then I'm yours.",
  "I'm not gentle by nature. My gentleness is only for you.",
  "I don't know what the future holds, but I know I want you in it.",
  "I won't let anyone bully you. Not now, not ever.",
  "You're not a distraction. You're my motivation.",
  "If you fall behind, I'll slow down and walk with you.",
  "I'm not afraid of losing games. I'm afraid of losing you.",
  "I don't chase happiness. I protect it.",
  "I may look cold, but everything I do is serious.",
  "As long as you're here, I'm home.",
  "I don't need applause. I need you.",
  "You don't need to grow up so fast. I'm here.",
  "I'll handle the hard parts. You just stay happy.",
  "I don't talk much, but I'll always show up.",
  "If you believe in me, I'll win for you.",
  "I don't regret meeting you. Not even once.",
  "From now on, your future includes me.",
];

/* ───────────────────── HELPERS ───────────────────── */

const randomQuote = () =>
  HAN_SHANGYAN_QUOTES[Math.floor(Math.random() * HAN_SHANGYAN_QUOTES.length)];

const isAdmin = (message) => message.author.username === CONFIG.ADMIN_NAME;

/* ───────────────────── EVENTS ───────────────────── */

client.on(Events.MessageCreate, async (message) => {
  if (message.content !== '!webhook') return;
  if (!isAdmin(message)) {
    return message.reply(`Only \`${CONFIG.ADMIN_NAME}\` can set up the K&K announcer webhook.`);
  }

  const webhooks = await message.channel.fetchWebhooks();
  const existingWebhook = webhooks.find((w) => w.owner?.id === client.user.id);

  if (existingWebhook) {
    return message.reply('Announcer webhook already exists.');
  }

  try {
    const webhook = await message.channel.createWebhook({
      name: CONFIG.WEBHOOK_NAME,
    });

    const embed = new EmbedBuilder()
      .setTitle('Announcer Webhook Created!')
      .setDescription(webhook.url)
      .setFooter({ text: `“${randomQuote()}” — Gun` })
      .setColor(0xe4bfc8);

    await message.reply({ embeds: [embed] });
  } catch (err) {
    console.error('Webhook creation failed:', err);
    message.reply('Failed to create announcer webhook.');
  }
});

client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isButton() || interaction.customId !== 'checkin') return;

  const guild = client.guilds.cache.get(CONFIG.TARGET_GUILD_ID);
  if (!guild) {
    return interaction.reply({
      content: `Could not access guild (${CONFIG.TARGET_GUILD_ID}).`,
      flags: MessageFlags.Ephemeral,
    });
  }

  const role = guild.roles.cache.find(r => r.name === CONFIG.ROLE_NAME);
  if (!role) {
    return interaction.reply({
      content: `Role **${CONFIG.ROLE_NAME}** not found in **${guild.name}**.`,
      flags: MessageFlags.Ephemeral,
    });
  }

  let member;
  try {
    member = await guild.members.fetch(interaction.user.id);
  } catch {
    return interaction.reply({
      content: `You're not a member of **${guild.name}**.`,
      flags: MessageFlags.Ephemeral,
    });
  }

  const alreadyHasRole = member.roles.cache.has(role.id);

  if (!alreadyHasRole) {
    try {
      await member.roles.add(role);
    } catch (err) {
      console.error('Role assignment failed:', err);
      return interaction.reply({
        content: 'Failed to assign role. Check bot permissions.',
        flags: MessageFlags.Ephemeral,
      });
    }
  }

  return interaction.reply({
    content: alreadyHasRole
      ? `You're already checked in at **${guild.name}**.`
      : `Checked in at **${guild.name}**! Assigned **${role.name}**.`,
    flags: MessageFlags.Ephemeral,
  });
});

/* ───────────────────── START ───────────────────── */

client.login("MTQ1NTgyMTI2MjY4NDE2NDE5Ng.G3LcQS.pGCfGOqCBzZOfRsT-ry8Hr9_aqt7IRJefiaDKE");
