#include "ansi_escape.h"
#include "log.h"
#include <iostream>
#include <sstream>
#include <fstream>
using namespace std;

#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

static const char ESC = 0x1B;
static const string esc = string{ESC} + "[";
static const string cursor_on  = esc + "?25h";
static const string cursor_off = esc + "?25l";
static const string track_on   = esc + "?1002h";
static const string track_off  = esc + "?1002l";
static const string mouse_on   = esc + "?9h";
static const string mouse_off  = esc + "?9l";
static const string clear_term = esc + "2J";
static const string clean_line = esc + "K";
static const string save_pos   = esc + "s";
static const string restore_pos= esc + "u";
static const string color_reset= esc + "0m";

static void dump_stdin()
{
    struct timeval tv { 0L, 0L };
    fd_set fds;
    unsigned char c;

    while (true)
    {
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        if (!select(1, &fds, NULL, NULL, &tv))
            break;

        read(0, &c, sizeof(c));
    }
}

static string set_color(const Color& fg, const Color& bg, int depth)
{
    stringstream ss;
    if (depth == 8)
    {
    }
    else if (depth == 256)
    {
    }
    else // 24 bit rgb
    {
        ss << esc;
        int r = (fg.rgb >> 16) & 0xff;
        int g = (fg.rgb >>  8) & 0xff;
        int b = (fg.rgb >>  0) & 0xff;
        ss << "38;2;" << r << ";" << g << ";" << b << "m";

        ss << esc;
        r = (bg.rgb >> 16) & 0xff;
        g = (bg.rgb >>  8) & 0xff;
        b = (bg.rgb >>  0) & 0xff;
        ss << "48;2;" << r << ";" << g << ";" << b << "m";
    }
    return ss.str();
}

string set_pos(int x, int y)
{
    stringstream ss;
    ss << esc << y << ";" << x << "f";
    return ss.str();
}

void refresh()
{
    cout << flush;
}

static void print(AnsiFrameState* pf, int x, int y, const Cell& cell)
{
    cout << set_pos(x, y);
    cout << set_color(cell.fg, cell.bg, 16777216);
    cout << cell.value;
    // cout << color_reset;
    cout << flush;
}

AnsiEscapeTerm::~AnsiEscapeTerm()
{
    close();
}

bool AnsiEscapeTerm::update()
{
    refresh();

    dump_stdin();

    return true;
}

bool AnsiEscapeTerm::open()
{
    if (_original)
    {
        cerr << "terminal is already open\n";
        return false;
    }

    //save current settings
    _original = new termios;
    ::tcgetattr(STDIN_FILENO, _original);

    cout << cursor_off;

    //put in raw mod
    termios raw;
    ::cfmakeraw(&raw);
    ::tcsetattr(STDIN_FILENO, TCSANOW, &raw);

    //switch to alternative buffer screen
    // cout << esc << "47h";

    //enable mouse tracking
    cout << mouse_on;

    cout << clear_term << set_pos(1, 1) << flush;
    return true;
}

void AnsiEscapeTerm::close()
{
    dump_stdin();

    // disable mouse tracking
    cout << mouse_off;
    cout << cursor_on;
    if (_original)
    {
        ::tcsetattr(STDIN_FILENO, TCSANOW, _original);
    }
    delete _original;
    _original = nullptr;
    _states.clear();
    cout << set_pos(1, 1);
    cout << flush;
}

bool AnsiEscapeTerm::onAdd(Frame* pf)
{
    _states[pf] = {};
    return true;
}

void AnsiEscapeTerm::onWrite(Frame* pf, int x, int y, const Cell& cell)
{
    if (pf->scrolling())
    {
        ofstream flog("log", fstream::app);
        flog << cell.value;
        flog.close();
    }
    else
    {
        auto& state = _states[pf];
        print(&state, x, y, cell);
    }
}

void AnsiEscapeTerm::onResolution(Frame* pWhichFrame)
{
}

tuple<int, int> AnsiEscapeTerm::maxResolution() const
{
    // TODO: handle SIGWINCH for resize
    // see signals.h
    int cols = 80;
    int lines = 24;

#ifdef TIOCGSIZE
    struct ttysize ts;
    ioctl(STDIN_FILENO, TIOCGSIZE, &ts);
    cols = ts.ts_cols;
    lines = ts.ts_lines;
#elif defined(TIOCGWINSZ)
    struct winsize ts;
    ioctl(STDIN_FILENO, TIOCGWINSZ, &ts);
    cols = ts.ws_col;
    lines = ts.ws_row;
#endif /* TIOCGSIZE */

    return std::make_tuple(cols, lines);
}