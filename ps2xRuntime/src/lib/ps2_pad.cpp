#include "runtime/ps2_pad.h"
#include "ps2_host_backend.h"
#include <algorithm>
#include <cmath>
#include <cstring>

namespace
{
    constexpr uint8_t kPadAnalogMarker = 0x73;
    constexpr uint8_t kPadStickCenter = 0x80;

    uint8_t axisToByte(float axis)
    {
        const float clamped = std::clamp(axis, -1.0f, 1.0f);
        return static_cast<uint8_t>(std::lround((clamped + 1.0f) * 127.5f));
    }

    constexpr uint16_t PAD_LEFT = 0x0080u;
    constexpr uint16_t PAD_DOWN = 0x0040u;
    constexpr uint16_t PAD_RIGHT = 0x0020u;
    constexpr uint16_t PAD_UP = 0x0010u;
    constexpr uint16_t PAD_START = 0x0008u;
    constexpr uint16_t PAD_R3 = 0x0004u;
    constexpr uint16_t PAD_L3 = 0x0002u;
    constexpr uint16_t PAD_SELECT = 0x0001u;
    constexpr uint16_t PAD_SQUARE = 0x8000u;
    constexpr uint16_t PAD_CROSS = 0x4000u;
    constexpr uint16_t PAD_CIRCLE = 0x2000u;
    constexpr uint16_t PAD_TRIANGLE = 0x1000u;
    constexpr uint16_t PAD_R1 = 0x0800u;
    constexpr uint16_t PAD_L1 = 0x0400u;
    constexpr uint16_t PAD_R2 = 0x0200u;
    constexpr uint16_t PAD_L2 = 0x0100u;
}

bool PSPadBackend::readState(int port, int slot, uint8_t *data, size_t size)
{
    if (!data || size < 32)
        return false;

    std::memset(data, 0, 32);
    data[0] = 0x01;
    data[1] = kPadAnalogMarker;
    data[2] = 0xFF;
    data[3] = 0xFF;
    data[4] = data[5] = data[6] = data[7] = kPadStickCenter;

    if (port != 0 || slot != 0 || !IsWindowReady())
        return true;

    uint16_t btns = 0xFFFFu;
    constexpr int kGamepad = 0;
    auto clearBit = [&btns](uint16_t mask)
    { btns &= ~mask; };

    if (IsGamepadAvailable(kGamepad))
    {
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_LEFT_FACE_UP))
            clearBit(PAD_UP);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_LEFT_FACE_DOWN))
            clearBit(PAD_DOWN);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_LEFT_FACE_LEFT))
            clearBit(PAD_LEFT);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_LEFT_FACE_RIGHT))
            clearBit(PAD_RIGHT);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_RIGHT_FACE_DOWN))
            clearBit(PAD_CROSS);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_RIGHT_FACE_RIGHT))
            clearBit(PAD_CIRCLE);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_RIGHT_FACE_LEFT))
            clearBit(PAD_SQUARE);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_RIGHT_FACE_UP))
            clearBit(PAD_TRIANGLE);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_LEFT_TRIGGER_1))
            clearBit(PAD_L1);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_RIGHT_TRIGGER_1))
            clearBit(PAD_R1);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_LEFT_TRIGGER_2))
            clearBit(PAD_L2);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_RIGHT_TRIGGER_2))
            clearBit(PAD_R2);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_MIDDLE_RIGHT))
            clearBit(PAD_START);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_MIDDLE_LEFT))
            clearBit(PAD_SELECT);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_LEFT_THUMB))
            clearBit(PAD_L3);
        if (IsGamepadButtonDown(kGamepad, GAMEPAD_BUTTON_RIGHT_THUMB))
            clearBit(PAD_R3);

        data[6] = axisToByte(GetGamepadAxisMovement(kGamepad, GAMEPAD_AXIS_LEFT_X));
        data[7] = axisToByte(GetGamepadAxisMovement(kGamepad, GAMEPAD_AXIS_LEFT_Y));
        data[4] = axisToByte(GetGamepadAxisMovement(kGamepad, GAMEPAD_AXIS_RIGHT_X));
        data[5] = axisToByte(GetGamepadAxisMovement(kGamepad, GAMEPAD_AXIS_RIGHT_Y));
    }

    // PCSX2 default keyboard bindings (pcsx2/Input/InputManager.cpp:1786-1812)
    if (IsKeyDown(KEY_UP))
        clearBit(PAD_UP);
    if (IsKeyDown(KEY_RIGHT))
        clearBit(PAD_RIGHT);
    if (IsKeyDown(KEY_DOWN))
        clearBit(PAD_DOWN);
    if (IsKeyDown(KEY_LEFT))
        clearBit(PAD_LEFT);
    if (IsKeyDown(KEY_I))
        clearBit(PAD_TRIANGLE);
    if (IsKeyDown(KEY_L))
        clearBit(PAD_CIRCLE);
    if (IsKeyDown(KEY_K))
        clearBit(PAD_CROSS);
    if (IsKeyDown(KEY_J))
        clearBit(PAD_SQUARE);
    if (IsKeyDown(KEY_Q))
        clearBit(PAD_L1);
    if (IsKeyDown(KEY_ONE))
        clearBit(PAD_L2);
    if (IsKeyDown(KEY_TWO))
        clearBit(PAD_L3);
    if (IsKeyDown(KEY_E))
        clearBit(PAD_R1);
    if (IsKeyDown(KEY_THREE))
        clearBit(PAD_R2);
    if (IsKeyDown(KEY_FOUR))
        clearBit(PAD_R3);
    if (IsKeyDown(KEY_ENTER) || IsKeyDown(KEY_KP_ENTER))
        clearBit(PAD_START);
    if (IsKeyDown(KEY_BACKSPACE))
        clearBit(PAD_SELECT);

    auto applyKeyAxis = [](int negKey, int posKey, uint8_t &outAxis)
    {
        if (IsKeyDown(negKey) || IsKeyDown(posKey))
        {
            const int dir = (IsKeyDown(posKey) ? 1 : 0) - (IsKeyDown(negKey) ? 1 : 0);
            outAxis = (dir < 0) ? 0x00u : ((dir > 0) ? 0xFFu : kPadStickCenter);
        }
    };
    applyKeyAxis(KEY_A, KEY_D, data[6]); // Left Stick X
    applyKeyAxis(KEY_W, KEY_S, data[7]); // Left Stick Y
    applyKeyAxis(KEY_F, KEY_H, data[4]); // Right Stick X
    applyKeyAxis(KEY_T, KEY_G, data[5]); // Right Stick Y

    data[2] = static_cast<uint8_t>(btns & 0xFF);
    data[3] = static_cast<uint8_t>(btns >> 8);
    return true;
}
