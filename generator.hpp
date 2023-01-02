#pragma once
#include <coroutine>
#include <cstddef>
#include <exception>
#include <iterator>
#include <optional>
#include <range/v3/detail/range_access.hpp>
#include <range/v3/view/facade.hpp>
#include <utility>
#include <variant>

template <typename T>
struct Generator : public ranges::view_facade<Generator<T>> {
  friend ranges::range_access;
  struct promise_type {
    auto get_return_object() noexcept { return Generator{*this}; };
    std::suspend_always initial_suspend() const noexcept { return {}; };
    std::suspend_always final_suspend() const noexcept { return {}; };

    void unhandled_exception() { result = std::current_exception(); };

    template <std::convertible_to<T> From>
    std::suspend_always yield_value(const From &value) {
      result = std::addressof(value);
      return {};
    }

    template <std::convertible_to<T> From>
    std::suspend_always yield_value(From &&value) {
      result = std::addressof(value);
      return {};
    }

    void return_void() noexcept { result = std::monostate(); }

    void throw_if_exception() {
      if (std::holds_alternative<std::exception_ptr>(result))
        std::rethrow_exception(std::get<std::exception_ptr>(result));
    }

    bool has_value() { return !std::holds_alternative<std::monostate>(result); }
    T &get_value() { return *std::get<T *>(result); }

  private:
    std::variant<std::monostate, T *, std::exception_ptr> result;
  };

  struct Cursor {
    Cursor() noexcept = default;
    explicit Cursor(const std::coroutine_handle<promise_type> &coro) noexcept
        : coro{&coro} {}

    bool equal(const Cursor &other) const { return this->coro == other.coro; };

    void next() {
      assert(coro != nullptr);
      assert(!coro->done());

      coro->resume();
      if (coro->done()) {
        auto handle = std::exchange(coro, nullptr);
        handle->promise().throw_if_exception();
      }
    }

    T &read() const noexcept {
      assert(coro != nullptr);
      assert(!coro->done());
      return coro->promise().get_value();
    }

  private:
    const std::coroutine_handle<promise_type> *coro;
  };

  Generator(Generator &&other) noexcept
      : coro{std::exchange(other.coro, nullptr)} {}

  Generator &operator=(Generator &&other) noexcept {
    if (coro)
      coro.destroy();
    coro = std::exchange(other.coro, nullptr);
  };

  ~Generator() {
    if (coro)
      coro.destroy();
  };

  Cursor begin_cursor() const {
    if (coro.done())
      return end_cursor();

    auto i = Cursor(coro);
    if (!coro.promise().has_value())
      i.next();

    return i;
  };
  Cursor end_cursor() const noexcept { return Cursor{}; };

private:
  explicit Generator(promise_type &promise) noexcept
      : coro{std::coroutine_handle<promise_type>::from_promise(promise)} {};

  std::coroutine_handle<promise_type> coro;
};
