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

// ---- expanded surface (2026-08): records, systems, collectibles -----

struct Waypoint {
    Vec3 pos;
    float wait_seconds;
    std::uint32_t flags;
};

struct PatrolRoute {
    Waypoint waypoints[12];
    std::uint32_t count;
    std::uint32_t loop_index;
};

struct LeaderboardEntry {
    Player *player;
    std::uint32_t score;
    std::uint32_t rank;
};

struct DialogLine {
    const char *text;
    const char *speaker;
    std::uint32_t flags;
};

struct DialogNode {
    DialogLine line;
    DialogNode *options[4];
    DialogNode *next;
};

template <class T>
struct ArrayRef {
    T *data;
    std::size_t len;
};

class Renderable {
public:
    virtual ~Renderable();
    virtual void render() const = 0;
    std::uint32_t mesh_id() const;

protected:
    std::uint32_t mesh_id_ = 0;
};

class Collectible : public Entity, public Renderable {
public:
    Collectible(std::uint32_t id, const char *label, std::uint32_t value);
    ~Collectible() override;

    const char *kind() const override;
    void tick(World &world) override;
    int score() const override;
    void render() const override;

    std::uint32_t value() const;
    const char *label() const;

private:
    const char *label_;
    std::uint32_t value_;
    std::uint32_t weight_;
};

class System {
public:
    virtual ~System();
    virtual const char *name() const = 0;
    virtual void update(World &world, float dt) = 0;
};

class PhysicsSystem final : public System {
public:
    ~PhysicsSystem() override;
    const char *name() const override;
    void update(World &world, float dt) override;

private:
    std::uint32_t steps_ = 0;
    std::uint32_t collisions_ = 0;
};

class AISystem final : public System {
public:
    ~AISystem() override;
    const char *name() const override;
    void update(World &world, float dt) override;

private:
    std::uint32_t decisions_ = 0;
    std::uint32_t path_recomputes_ = 0;
};

class RenderSystem final : public System {
public:
    ~RenderSystem() override;
    const char *name() const override;
    void update(World &world, float dt) override;

private:
    std::uint32_t frames_ = 0;
    std::uint32_t draw_calls_ = 0;
};

class AudioSystem final : public System {
public:
    ~AudioSystem() override;
    const char *name() const override;
    void update(World &world, float dt) override;

private:
    std::uint32_t cues_ = 0;
    std::uint32_t played_ = 0;
};

class Guild {
public:
    Guild();
    void add_member(Player *member);
    Player *lead() const;
    std::uint32_t member_count() const;
    std::uint32_t treasury() const;
    void add_funds(std::uint32_t amount);

private:
    Player *members_[16];
    Player *lead_;
    std::uint32_t member_count_;
    std::uint32_t treasury_;
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

    void register_system(System *system);
    void tick_systems(float dt);
    void add_leaderboard_entry(Player *player, std::uint32_t score);
    const LeaderboardEntry *top_entry() const;
    std::uint32_t leaderboard_count() const;

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
    // ---- expanded surface (2026-08): systems, patrols, leaderboard ----
    System *systems_[4];
    std::uint32_t system_count_;
    PatrolRoute patrols_[8];
    std::uint32_t patrol_count_;
    LeaderboardEntry leaderboard_[16];
    std::uint32_t leaderboard_count_;
    std::uint32_t simulation_time_;
};

/* globals for global-reference scans */
extern World g_world;
extern const char *g_scene_name;
extern Player *g_main_player;

int run_demo();

/* additional expanded entry points */
int run_systems_demo();
int run_patrol_demo();
int run_dialog_demo();
int run_guild_demo();
int run_render_demo();
int run_templated_demo();

} // namespace fixture
