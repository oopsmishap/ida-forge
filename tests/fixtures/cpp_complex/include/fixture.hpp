#pragma once

#include <cstddef>
#include <cstdint>

namespace fixture {

class World;
class Player;
class Merchant;
class Enemy;
class Entity;

struct Vec3 {
    float x;
    float y;
    float z;
};

struct Transform {
    Vec3 position;
    Vec3 rotation;
    Vec3 scale;
    float matrix[16];
};

struct StatusEffect {
    const char *name;
    int duration;
    float magnitude;
    StatusEffect *next;
};

struct InventoryItem {
    std::uint32_t item_id;
    const char *label;
    std::uint32_t weight;
    std::uint32_t value;
    std::uint8_t flags;
    std::uint8_t quality;
    std::uint16_t padding;
};

struct InventorySlot {
    InventoryItem *item;
    std::uint32_t count;
    bool equipped;
    bool reserved;
    std::uint16_t lock_id;
};

struct Inventory {
    InventorySlot slots[32];
    Inventory *overflow;
    Player *owner;
    World *world;
    std::uint32_t slot_count;
    std::uint32_t max_weight;
};

struct QuestStep {
    const char *description;
    bool completed;
    std::uint8_t priority;
    std::uint8_t stage;
    std::uint8_t padding[4];
};

struct Quest {
    const char *title;
    QuestStep steps[8];
    Quest *next;
    Player *issuer;
    std::uint32_t reward_gold;
    std::uint32_t reward_xp;
};

struct SceneNode {
    SceneNode *parent;
    SceneNode *children[8];
    Entity *entity;
    char tag[32];
};

class Entity {
public:
    explicit Entity(std::uint32_t id);
    virtual ~Entity();

    virtual const char *kind() const = 0;
    virtual void tick(World &world) = 0;
    virtual int score() const;

    std::uint32_t id() const;

protected:
    std::uint32_t id_;
    Transform transform_;
    StatusEffect *active_effects_;
};

class ActorMixin {
public:
    virtual ~ActorMixin();
    virtual int mixin_value() const = 0;
};

class LivingEntity : public Entity, public ActorMixin {
public:
    LivingEntity(std::uint32_t id, Inventory *inventory);
    ~LivingEntity() override;

    int mixin_value() const override;
    int score() const override;
    Inventory *inventory() const;

protected:
    Inventory *inventory_;
    std::uint32_t health_;
    std::uint32_t stamina_;
    std::uint32_t mana_;
    std::uint32_t armor_;
    std::uint32_t resistance_;
    std::uint32_t strength_;
    std::uint32_t agility_;
    std::uint32_t intelligence_;
    std::uint32_t luck_;
    StatusEffect *buff_head_;
};

class Player final : public LivingEntity {
public:
    Player(std::uint32_t id, Inventory *inventory, Quest *quest_head);
    ~Player() override;

    const char *kind() const override;
    void tick(World &world) override;
    int score() const override;

    Quest *quests() const;
    World *world() const;
    void attach_world(World *world);

private:
    World *world_;
    Quest *quest_head_;
    InventoryItem *equipped_weapon_;
    InventoryItem *equipped_armor_;
    std::uint32_t experience_;
    std::uint32_t level_;
    std::uint32_t gold_;
};

class Merchant final : public LivingEntity {
public:
    Merchant(std::uint32_t id, Inventory *inventory, Inventory *stock);
    ~Merchant() override;

    const char *kind() const override;
    void tick(World &world) override;
    int score() const override;

    Inventory *stock() const;

private:
    Inventory *stock_;
    InventoryItem *special_offer_;
    std::uint32_t reputation_;
    std::uint32_t tariff_;
    std::uint32_t route_index_;
};

class Enemy final : public LivingEntity {
public:
    Enemy(std::uint32_t id, Inventory *inventory, Player *target);
    ~Enemy() override;

    const char *kind() const override;
    void tick(World &world) override;
    int score() const override;

    Player *target() const;

private:
    Player *target_;
    Enemy *next_; 
    std::uint32_t aggressiveness_;
    std::uint32_t threat_;
    std::uint32_t patrol_index_;
};

class World {
public:
    World();
    ~World();

    void add_player(Player *player);
    void add_enemy(Enemy *enemy);
    void add_merchant(Merchant *merchant);
    void tick_all();
    int total_score() const;
    Entity *entity_at(std::size_t index) const;
    SceneNode *root();
    const SceneNode *root() const;

private:
    SceneNode root_;
    SceneNode nodes_[8];
    Player *player_;
    Merchant *merchant_;
    Enemy *enemies_[8];
    Entity *entities_[16];
    Quest *quest_root_;
    Inventory *shared_inventory_;
    std::uint32_t frame_;
    std::uint32_t checksum_;
    std::uint32_t padding_[24];
};

int run_demo();

} // namespace fixture
