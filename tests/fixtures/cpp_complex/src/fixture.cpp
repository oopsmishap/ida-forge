#include "fixture.hpp"

#include <array>
#include <cmath>
#include <cstdio>

namespace fixture {

namespace {

void init_transform(Transform &transform, float bias) {
    transform.position = {bias, bias + 1.0f, bias + 2.0f};
    transform.rotation = {bias * 2.0f, bias * 2.0f + 1.0f, bias * 2.0f + 2.0f};
    transform.scale = {1.0f + bias, 1.0f + bias, 1.0f + bias};
    for (std::size_t i = 0; i < 16; ++i) {
        transform.matrix[i] = bias + static_cast<float>(i);
    }
}

void init_inventory(Inventory &inventory, Inventory *overflow, Player *owner, World *world) {
    inventory.overflow = overflow;
    inventory.owner = owner;
    inventory.world = world;
    inventory.slot_count = 0;
    inventory.max_weight = 250;
    for (std::size_t i = 0; i < 32; ++i) {
        inventory.slots[i] = {nullptr, 0, false, false, 0};
    }
}

void seed_inventory(
    Inventory &inventory,
    const std::array<InventoryItem, 6> &items,
    std::uint32_t item_offset
) {
    for (std::size_t i = 0; i < 6; ++i) {
        inventory.slots[i].item = const_cast<InventoryItem *>(&items[(item_offset + i) % items.size()]);
        inventory.slots[i].count = 1 + static_cast<std::uint32_t>(i);
        inventory.slots[i].equipped = (i == 0);
        inventory.slots[i].reserved = (i == 5);
        inventory.slots[i].lock_id = static_cast<std::uint16_t>(0x40 + i);
    }
    inventory.slot_count = 6;
}

struct FixtureScene {
    World world;
    Inventory player_inventory;
    Inventory bank_inventory;
    Inventory merchant_inventory;
    Quest quest_chain;
    Quest quest_tail;
    Player player;
    Merchant merchant;
    std::array<Enemy, 3> enemies;
    std::array<InventoryItem, 6> items;
    Guild guild;
    DialogNode dialog_root;
    DialogNode dialog_leaf;
    ArrayRef<QuestStep> active_steps;
    Collectible relic;

    FixtureScene()
        : world(), player_inventory(), bank_inventory(), merchant_inventory(), quest_chain(),
          quest_tail(), player(0x1001, &player_inventory, &quest_chain),
          merchant(0x2001, &merchant_inventory, &bank_inventory),
          enemies{{
              Enemy(0x3001, &bank_inventory, &player),
              Enemy(0x3002, &bank_inventory, &player),
              Enemy(0x3003, &bank_inventory, &player),
          }},
          items{{
              {0x101, "iron_sword", 12, 120, 1, 3, 0},
              {0x102, "oak_shield", 18, 90, 2, 2, 0},
              {0x103, "mana_potion", 1, 45, 4, 1, 0},
              {0x104, "ancient_key", 2, 0, 8, 5, 0},
              {0x105, "merchant_token", 1, 10, 16, 4, 0},
              {0x106, "wolf_pelt", 3, 30, 32, 2, 0},
          }},
          relic(0x4001, "relic_of_order", 999) {
        init_inventory(player_inventory, &bank_inventory, &player, &world);
        init_inventory(bank_inventory, &merchant_inventory, nullptr, &world);
        init_inventory(merchant_inventory, nullptr, nullptr, &world);
        seed_inventory(player_inventory, items, 0);
        seed_inventory(bank_inventory, items, 2);
        seed_inventory(merchant_inventory, items, 4);

        quest_chain.title = "recover_the_relic";
        quest_chain.steps[0] = {"find_the_map", false, 1, 0, {0, 0, 0, 0}};
        quest_chain.steps[1] = {"reach_the_cavern", false, 2, 0, {0, 0, 0, 0}};
        quest_chain.steps[2] = {"defeat_the_warden", false, 3, 0, {0, 0, 0, 0}};
        quest_chain.steps[3] = {"take_the_relic", false, 4, 0, {0, 0, 0, 0}};
        quest_chain.steps[4] = {"return_to_the_town", false, 5, 0, {0, 0, 0, 0}};
        quest_chain.steps[5] = {"collect_the_reward", false, 6, 0, {0, 0, 0, 0}};
        quest_chain.steps[6] = {"bonus_objective", false, 7, 0, {0, 0, 0, 0}};
        quest_chain.steps[7] = {"epilogue", false, 8, 0, {0, 0, 0, 0}};
        quest_chain.next = &quest_tail;
        quest_chain.issuer = &player;
        quest_chain.reward_gold = 250;
        quest_chain.reward_xp = 900;

        quest_tail.title = "merchant_favor";
        quest_tail.steps[0] = {"deliver_the_stock", true, 1, 0, {0, 0, 0, 0}};
        quest_tail.steps[1] = {"close_the_deal", false, 2, 0, {0, 0, 0, 0}};
        quest_tail.next = nullptr;
        quest_tail.issuer = &player;
        quest_tail.reward_gold = 80;
        quest_tail.reward_xp = 120;

        world.add_player(&player);
        world.add_merchant(&merchant);
        world.add_enemy(&enemies[0]);
        world.add_enemy(&enemies[1]);
        world.add_enemy(&enemies[2]);

        guild.add_member(&player);
        guild.add_funds(150);

        dialog_root.line = {"hello_traveler", "innkeeper", 0x01};
        dialog_leaf.line = {"good_luck_traveler", "innkeeper", 0x02};
        dialog_root.options[0] = &dialog_leaf;
        dialog_root.next = nullptr;
        dialog_leaf.options[0] = nullptr;
        dialog_leaf.next = nullptr;

        active_steps.data = quest_chain.steps;
        active_steps.len = 8;
    }

    int run() {
        world.tick_all();
        world.tick_all();
        return world.total_score();
    }
};

} // namespace

Entity::Entity(std::uint32_t id) : id_(id), active_effects_(nullptr) {
    init_transform(transform_, static_cast<float>(id));
}

Entity::~Entity() = default;

int Entity::score() const {
    return static_cast<int>(id_ + static_cast<std::uint32_t>(transform_.position.x) +
                            static_cast<std::uint32_t>(transform_.rotation.y));
}

std::uint32_t Entity::id() const {
    return id_;
}

ActorMixin::~ActorMixin() = default;

LivingEntity::LivingEntity(std::uint32_t id, Inventory *inventory)
    : Entity(id), inventory_(inventory), health_(100), stamina_(80), mana_(40), armor_(10),
      resistance_(6), strength_(14), agility_(12), intelligence_(9), luck_(3), buff_head_(nullptr) {}

LivingEntity::~LivingEntity() = default;

int LivingEntity::mixin_value() const {
    return static_cast<int>(health_ + stamina_ + mana_ + armor_ + resistance_ + strength_ +
                            agility_ + intelligence_ + luck_);
}

int LivingEntity::score() const {
    return Entity::score() + mixin_value();
}

Inventory *LivingEntity::inventory() const {
    return inventory_;
}

Player::Player(std::uint32_t id, Inventory *inventory, Quest *quest_head)
    : LivingEntity(id, inventory), world_(nullptr), quest_head_(quest_head), equipped_weapon_(nullptr),
      equipped_armor_(nullptr), experience_(0), level_(1), gold_(100) {}

Player::~Player() = default;

const char *Player::kind() const {
    return "Player";
}

void Player::tick(World &world) {
    world_ = &world;
    experience_ += 13;
    if (experience_ > 100) {
        experience_ -= 100;
        ++level_;
    }
    gold_ += 1;
    if (inventory_ && inventory_->slots[0].item) {
        equipped_weapon_ = inventory_->slots[0].item;
    }
    if (inventory_ && inventory_->slots[1].item) {
        equipped_armor_ = inventory_->slots[1].item;
    }
}

int Player::score() const {
    return LivingEntity::score() + static_cast<int>(experience_ + level_ + gold_);
}

Quest *Player::quests() const {
    return quest_head_;
}

World *Player::world() const {
    return world_;
}

void Player::attach_world(World *world) {
    world_ = world;
}

Merchant::Merchant(std::uint32_t id, Inventory *inventory, Inventory *stock)
    : LivingEntity(id, inventory), stock_(stock), special_offer_(nullptr), reputation_(25),
      tariff_(7), route_index_(0) {}

Merchant::~Merchant() = default;

const char *Merchant::kind() const {
    return "Merchant";
}

void Merchant::tick(World &world) {
    (void)world;
    if (stock_ && stock_->slots[0].item) {
        special_offer_ = stock_->slots[0].item;
    }
    route_index_ = (route_index_ + 1) % 4;
    reputation_ += tariff_;
}

int Merchant::score() const {
    return LivingEntity::score() + static_cast<int>(reputation_ + tariff_ + route_index_);
}

Inventory *Merchant::stock() const {
    return stock_;
}

Enemy::Enemy(std::uint32_t id, Inventory *inventory, Player *target)
    : LivingEntity(id, inventory), target_(target), next_(nullptr), aggressiveness_(9), threat_(17),
      patrol_index_(0) {}

Enemy::~Enemy() = default;

const char *Enemy::kind() const {
    return "Enemy";
}

void Enemy::tick(World &world) {
    (void)world;
    patrol_index_ = (patrol_index_ + 3) % 11;
    threat_ += aggressiveness_;
    if (target_ != nullptr) {
        threat_ += target_->id() & 3U;
    }
}

int Enemy::score() const {
    return LivingEntity::score() + static_cast<int>(aggressiveness_ + threat_ + patrol_index_);
}

Player *Enemy::target() const {
    return target_;
}

World::World()
    : player_(nullptr), merchant_(nullptr), quest_root_(nullptr), shared_inventory_(nullptr),
      frame_(0), checksum_(0) {
    root_.parent = nullptr;
    root_.entity = nullptr;
    root_.tag[0] = '\0';
    for (std::size_t i = 0; i < 8; ++i) {
        root_.children[i] = &nodes_[i];
        nodes_[i].parent = &root_;
        nodes_[i].entity = nullptr;
        nodes_[i].tag[0] = static_cast<char>('a' + i);
        nodes_[i].tag[1] = '\0';
        for (std::size_t j = 0; j < 8; ++j) {
            nodes_[i].children[j] = nullptr;
        }
    }
    for (std::size_t i = 0; i < 16; ++i) {
        entities_[i] = nullptr;
    }
    for (std::size_t i = 0; i < 8; ++i) {
        enemies_[i] = nullptr;
    }
    for (std::size_t i = 0; i < 24; ++i) {
        padding_[i] = static_cast<std::uint32_t>(i * 17);
    }
}

World::~World() = default;

void World::add_player(Player *player) {
    player_ = player;
    if (player_ != nullptr) {
        player_->attach_world(this);
        entities_[0] = player_;
        root_.children[0]->entity = player_;
    }
}

void World::add_enemy(Enemy *enemy) {
    for (std::size_t i = 0; i < 8; ++i) {
        if (enemies_[i] == nullptr) {
            enemies_[i] = enemy;
            entities_[i + 1] = enemy;
            root_.children[i + 1]->entity = enemy;
            return;
        }
    }
}

void World::add_merchant(Merchant *merchant) {
    merchant_ = merchant;
    entities_[9] = merchant_;
    root_.children[7]->entity = merchant_;
}

void World::tick_all() {
    ++frame_;
    for (Entity *entity : entities_) {
        if (entity != nullptr) {
            entity->tick(*this);
            checksum_ ^= entity->score() + static_cast<int>(frame_);
        }
    }
}

int World::total_score() const {
    int total = 0;
    for (Entity *entity : entities_) {
        if (entity != nullptr) {
            total += entity->score();
        }
    }
    return total + static_cast<int>(checksum_);
}

Entity *World::entity_at(std::size_t index) const {
    return index < 16 ? entities_[index] : nullptr;
}

SceneNode *World::root() {
    return &root_;
}

const SceneNode *World::root() const {
    return &root_;
}

struct RuntimeRoot {
    FixtureScene scene;
    std::array<std::uint8_t, 0x220> bookkeeping;
    World *scene_world;
    Quest *quest_anchor;

    RuntimeRoot()
        : scene(), bookkeeping{}, scene_world(&scene.world), quest_anchor(&scene.quest_chain) {
        for (std::size_t i = 0; i < bookkeeping.size(); ++i) {
            bookkeeping[i] = static_cast<std::uint8_t>(i ^ 0x5A);
        }
    }

    int run() {
        scene_world->tick_all();
        scene_world->tick_all();
        bookkeeping[0] ^= static_cast<std::uint8_t>(scene_world->total_score());
        if (quest_anchor != nullptr && quest_anchor->next != nullptr) {
            bookkeeping[1] ^= static_cast<std::uint8_t>(quest_anchor->next->reward_gold);
        }
        return scene_world->total_score() + bookkeeping[0] + bookkeeping[1];
    }
};

int run_demo() {
    FixtureScene scene;
    int status = scene.run() & 0xff;
    RuntimeRoot runtime;
    status ^= runtime.run() & 0xff;
    status ^= run_systems_demo();
    status ^= run_patrol_demo();
    status ^= run_dialog_demo();
    status ^= run_guild_demo();
    status ^= run_render_demo();
    status ^= run_templated_demo();
    return status & 0xff;
}

// ------------------------------------------------------------------ //
// Expanded surface (2026-08): globals, Renderable/System hierarchies, //
// Guild, patrols, dialogs, templates, simulation helpers.             //
// ------------------------------------------------------------------ //

World g_world;
const char *g_scene_name = "main_arena";
Player *g_main_player = nullptr;

namespace {

template <class T>
T clamp_value(T value, T low, T high) {
    return value < low ? low : (value > high ? high : value);
}

void seed_patrol(PatrolRoute *route, std::uint32_t count, float base) {
    route->count = count > 12 ? 12 : count;
    route->loop_index = 0;
    for (std::uint32_t i = 0; i < route->count; ++i) {
        route->waypoints[i].pos = {base + static_cast<float>(i),
                                   base + static_cast<float>(i) + 0.5f,
                                   base - static_cast<float>(i)};
        route->waypoints[i].wait_seconds = 1.0f + static_cast<float>(i) * 0.25f;
        route->waypoints[i].flags = 0x100U + i;
    }
}

float route_total_distance(const PatrolRoute *route) {
    float total = 0.0f;
    for (std::uint32_t i = 1; i < route->count; ++i) {
        const Waypoint &from = route->waypoints[i - 1];
        const Waypoint &to = route->waypoints[i];
        const float dx = to.pos.x - from.pos.x;
        const float dy = to.pos.y - from.pos.y;
        const float dz = to.pos.z - from.pos.z;
        total += std::sqrt(dx * dx + dy * dy + dz * dz);
    }
    return total;
}

int guard_bounds(World &world, float x, float y) {
    if (x < -100.0f || x > 100.0f) {
        return 0;
    }
    if (y < -100.0f || y > 100.0f) {
        return 0;
    }
    return world.total_score() > 0 ? 1 : 0;
}

int serialize_world_into(const World &world, char *buffer, std::size_t capacity) {
    const SceneNode *root = world.root();
    int written = std::snprintf(
        buffer, capacity, "frame=%u score=%d leaderboard=%u",
        world.leaderboard_count(), world.total_score(), world.leaderboard_count());
    if (written < 0) {
        return -1;
    }
    (void)root;
    return written;
}

} // namespace

Renderable::~Renderable() = default;

std::uint32_t Renderable::mesh_id() const {
    return mesh_id_;
}

Collectible::Collectible(std::uint32_t id, const char *label, std::uint32_t value)
    : Entity(id), Renderable(), label_(label), value_(value), weight_(1) {
    mesh_id_ = 0x7000U + id;
}

Collectible::~Collectible() = default;

const char *Collectible::kind() const {
    return "Collectible";
}

void Collectible::tick(World &object) {
    (void)object;
    weight_ += 1;
}

int Collectible::score() const {
    return static_cast<int>(value_ + mesh_id());
}

void Collectible::render() const {
    std::printf("[render] mesh=%u value=%u\n", mesh_id(), value_);
}

std::uint32_t Collectible::value() const {
    return value_;
}

const char *Collectible::label() const {
    return label_;
}

System::~System() = default;

PhysicsSystem::~PhysicsSystem() = default;

const char *PhysicsSystem::name() const {
    return "physics";
}

void PhysicsSystem::update(World &object, float dt) {
    (void)object;
    steps_ += 1;
    if (dt > 0.016f) {
        collisions_ += 1;
    }
}

AISystem::~AISystem() = default;

const char *AISystem::name() const {
    return "ai";
}

void AISystem::update(World &object, float dt) {
    (void)object;
    (void)dt;
    decisions_ += 1;
    path_recomputes_ += decisions_ % 4 == 0 ? 1 : 0;
}

RenderSystem::~RenderSystem() = default;

const char *RenderSystem::name() const {
    return "render";
}

void RenderSystem::update(World &object, float dt) {
    (void)object;
    (void)dt;
    frames_ += 1;
    draw_calls_ += 32;
}

AudioSystem::~AudioSystem() = default;

const char *AudioSystem::name() const {
    return "audio";
}

void AudioSystem::update(World &object, float dt) {
    (void)object;
    (void)dt;
    cues_ += 1;
    played_ += cues_;
}

void World::register_system(System *system) {
    if (system_count_ < 4) {
        systems_[system_count_] = system;
        system_count_ += 1;
    }
}

void World::tick_systems(float dt) {
    simulation_time_ += 1;
    for (std::uint32_t i = 0; i < system_count_; ++i) {
        if (systems_[i] != nullptr) {
            systems_[i]->update(*this, dt);
        }
    }
}

void World::add_leaderboard_entry(Player *player, std::uint32_t score) {
    if (leaderboard_count_ < 16) {
        leaderboard_[leaderboard_count_].player = player;
        leaderboard_[leaderboard_count_].score = score;
        leaderboard_[leaderboard_count_].rank = leaderboard_count_ + 1;
        leaderboard_count_ += 1;
    }
}

const LeaderboardEntry *World::top_entry() const {
    const LeaderboardEntry *best = nullptr;
    for (std::uint32_t i = 0; i < leaderboard_count_; ++i) {
        if (best == nullptr || leaderboard_[i].score > best->score) {
            best = &leaderboard_[i];
        }
    }
    return best;
}

std::uint32_t World::leaderboard_count() const {
    return leaderboard_count_;
}

Guild::Guild()
    : lead_(nullptr), member_count_(0), treasury_(0) {
    for (std::uint32_t i = 0; i < 16; ++i) {
        members_[i] = nullptr;
    }
}

void Guild::add_member(Player *member) {
    if (member_count_ >= 16) {
        return;
    }
    members_[member_count_] = member;
    member_count_ += 1;
    if (lead_ == nullptr) {
        lead_ = member;
    }
}

Player *Guild::lead() const {
    return lead_;
}

std::uint32_t Guild::member_count() const {
    return member_count_;
}

std::uint32_t Guild::treasury() const {
    return treasury_;
}

void Guild::add_funds(std::uint32_t amount) {
    treasury_ += amount;
}

float distance_between(const Vec3 &a, const Vec3 &b) {
    const float dx = b.x - a.x;
    const float dy = b.y - a.y;
    const float dz = b.z - a.z;
    return std::sqrt(dx * dx + dy * dy + dz * dz);
}

std::uint32_t clamp_u32(std::uint32_t value, std::uint32_t low, std::uint32_t high) {
    return clamp_value(value, low, high);
}

float clamp_f32(float value, float low, float high) {
    return clamp_value(value, low, high);
}

ArrayRef<QuestStep> quest_steps_of(const Quest &quest) {
    ArrayRef<QuestStep> steps;
    steps.data = const_cast<QuestStep *>(quest.steps);
    steps.len = 8;
    return steps;
}

int compute_path(const Vec3 &from, const Vec3 &to, Vec3 *out, std::uint32_t max_points) {
    std::uint32_t points = 0;
    for (std::uint32_t i = 0; i < max_points; ++i) {
        const float t = max_points > 1 ? static_cast<float>(i) / static_cast<float>(max_points - 1) : 0.0f;
        out[i].x = from.x + (to.x - from.x) * t;
        out[i].y = from.y + (to.y - from.y) * t;
        out[i].z = from.z + (to.z - from.z) * t;
        points += 1;
    }
    return static_cast<int>(points);
}

int bake_lighting(const World &world, float *out) {
    (void)world;
    out[0] = 0.35f;
    out[1] = 0.70f;
    out[2] = 1.05f;
    return 3;
}

void render_scene(const World &world) {
    (void)world;
    std::printf("[scene] %s\n", g_scene_name);
}

int simulate_frame(World &world, float dt) {
    world.tick_all();
    world.tick_systems(dt);
    return world.total_score();
}

int evaluate_quest_state(const Quest &quest, std::uint32_t *completed) {
    std::uint32_t done = 0;
    for (std::uint32_t i = 0; i < 8; ++i) {
        if (quest.steps[i].completed) {
            done += 1;
        }
    }
    *completed = done;
    return static_cast<int>(done);
}

int run_systems_demo() {
    PhysicsSystem physics;
    AISystem ai;
    RenderSystem render;
    AudioSystem audio;
    World local;
    local.register_system(&physics);
    local.register_system(&ai);
    local.register_system(&render);
    local.register_system(&audio);
    local.tick_systems(0.016f);
    local.tick_systems(0.05f);
    local.tick_systems(0.016f);
    const int guarded = guard_bounds(local, 10.0f, 10.0f);
    char buffer[128];
    const int serialized = serialize_world_into(local, buffer, sizeof(buffer));
    std::printf("[systems] score=%d guarded=%d serialized=%d\n",
                local.total_score(), guarded, serialized);
    return local.total_score() & 0xff;
}

int run_patrol_demo() {
    PatrolRoute patrols[8];
    for (std::uint32_t i = 0; i < 8; ++i) {
        seed_patrol(&patrols[i], 4U + i % 3U, static_cast<float>(i) * 4.0f);
    }
    float total = 0.0f;
    for (std::uint32_t i = 0; i < 8; ++i) {
        total += route_total_distance(&patrols[i]);
    }
    std::printf("[patrol] routes=8 distance=%.1f\n", total);
    return static_cast<int>(total) & 0xff;
}

int run_dialog_demo() {
    DialogNode greeting;
    DialogNode farewell;
    greeting.line = {"hello_traveler", "innkeeper", 0x01};
    farewell.line = {"good_luck_traveler", "innkeeper", 0x02};
    greeting.options[0] = &farewell;
    greeting.options[1] = nullptr;
    greeting.options[2] = nullptr;
    greeting.options[3] = nullptr;
    greeting.next = nullptr;
    farewell.options[0] = nullptr;
    farewell.options[1] = nullptr;
    farewell.options[2] = nullptr;
    farewell.options[3] = nullptr;
    farewell.next = nullptr;
    std::printf("[dialog] opening=%s speaker=%s\n",
                greeting.line.text, greeting.line.speaker);
    return greeting.options[0] != nullptr ? 1 : 0;
}

int run_guild_demo() {
    Inventory dummy;
    init_inventory(dummy, nullptr, nullptr, &g_world);
    Player lead(0x6001, &dummy, nullptr);
    Player deputy(0x6002, &dummy, nullptr);
    Guild guild;
    guild.add_member(&lead);
    guild.add_member(&deputy);
    guild.add_funds(400);
    std::printf("[guild] members=%u treasury=%u lead=%u\n",
                guild.member_count(), guild.treasury(), guild.lead()->id());
    return static_cast<int>(guild.treasury()) & 0xff;
}

int run_render_demo() {
    Inventory dummy;
    init_inventory(dummy, nullptr, nullptr, &g_world);
    Collectible crystal_a(0x5001, "crystal_a", 50);
    Collectible crystal_b(0x5002, "crystal_b", 75);
    Collectible crystal_c(0x5003, "crystal_c", 100);
    Renderable *table[3] = {&crystal_a, &crystal_b, &crystal_c};
    for (int i = 0; i < 3; ++i) {
        table[i]->render();
    }
    std::printf("[collectible] a=%s b=%s c=%s\n",
                crystal_a.label(), crystal_b.label(), crystal_c.label());
    return static_cast<int>(crystal_a.value() + crystal_b.value() + crystal_c.value()) & 0xff;
}

int run_templated_demo() {
    const int clamped_int = clamp_value(150, 0, 100);
    const float clamped_float = clamp_value(0.75f, 0.0f, 1.0f);
    int values[3] = {10, 20, 30};
    ArrayRef<int> ref{values, 3};
    int sum = 0;
    for (std::size_t i = 0; i < ref.len; ++i) {
        sum += ref.data[i];
    }
    std::printf("[templated] int=%d float=%.2f sum=%d\n",
                clamped_int, clamped_float, sum);
    return (clamped_int + sum) & 0xff;
}

} // namespace fixture
