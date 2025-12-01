import asyncio
# 简单延迟并打印
async def say_after():
    await asyncio.sleep(1)
    print("Hello after 1 second")
async def main_simple():
    task = asyncio.create_task(say_after())
    await task
    print("Simple done")
# --------------------
# 并发运行多个任务并等待全部完成
async def worker(name, delay):
    await asyncio.sleep(delay)
    print(f"Worker {name} finished after {delay}s")
async def main_concurrent():
    t1 = asyncio.create_task(worker("A", 1))
    t2 = asyncio.create_task(worker("B", 0.5))
    t3 = asyncio.create_task(worker("C", 0.2))
    await t1
    await t2
    await t3
    print("Concurrent workers done")
# --------------------
# 使用 gather 同时等待多个任务
async def main_gather():
    a = asyncio.create_task(worker("G1", 0.3))
    b = asyncio.create_task(worker("G2", 0.6))
    await asyncio.gather(a, b)
    print("Gather done")
# --------------------
# 使用 wait 返回已完成和未完成集合
async def main_wait():
    x = asyncio.create_task(worker("W1", 0.4))
    y = asyncio.create_task(worker("W2", 0.8))
    done, pending = await asyncio.wait({x, y}, return_when=asyncio.FIRST_COMPLETED)
    for d in done:
        print("One finished via wait")
    for p in pending:
        p.cancel()
    print("Wait done (cancelled pending)")
# 使用队列在生产者和消费者之间传递数据
async def producer(q):
    for i in range(3):
        await asyncio.sleep(0.2)
        await q.put(i)
        print("Produced", i)
    await q.put(None)
async def consumer(q):
    while True:
        item = await q.get()
        if item is None:
            break
        print("Consumed", item)
    print("Consumer done")
async def main_queue():
    q = asyncio.Queue()
    p = asyncio.create_task(producer(q))
    c = asyncio.create_task(consumer(q))
    await p
    await c
    print("Queue example done")
# --------------------
# 超时示例：wait_for
async def long_task():
    await asyncio.sleep(2)
    return "long done"
async def main_timeout():
    try:
        res = await asyncio.wait_for(long_task(), timeout=1.0)
        print(res)
    except asyncio.TimeoutError:
        print("Task timed out")
# --------------------
# 依次运行上面的示例（按顺序）
async def main():
    await main_simple()
    print("-" * 40)
    await main_concurrent()
    print("-" * 40)
    await main_gather()
    print("-" * 40)
    await main_wait()
    print("-" * 40)
    await main_queue()
    print("-" * 40)
    await main_timeout()
    print("-" * 40)
    print("All examples finished")

if __name__ == "__main__":
    asyncio.run(main())
