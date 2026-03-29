#include "fixture.hpp"

#include <array>

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
          }} {
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

int run_demo() {
    FixtureScene scene;
    return scene.run() & 0xff;
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
    RuntimeRoot runtime;
    return runtime.run() & 0xff;
}

} // namespace fixture
