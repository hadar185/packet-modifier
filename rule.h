struct address {
    int ip;
    int port;
};

struct filter {
    struct address src;
    struct address dst;
};

enum action_type {
    DROP = 0,
    ALTER = 1
};

struct action {
    enum action_type action_type;
    struct filter filter;
};

struct rule {
    struct filter filter;
    struct action action;
};