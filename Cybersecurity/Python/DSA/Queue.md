```python
# Queue implementation in Python

class Queue:

    def __init__(self):
        self.queue = []

    # Add an element
    def enqueue(self, item):
        self.queue.append(item)

    # Remove an element
    def dequeue(self):
        if len(self.queue) < 1:
            return None
        return self.queue.pop(0)

    # Display  the queue
    def display(self):
        print(self.queue)

    def size(self):
        return len(self.queue)

q = Queue()
q.enqueue(1)
q.enqueue(2)
q.enqueue(3)
q.enqueue(4)
q.enqueue(5)

q.display()

q.dequeue()

print("After removing an element")
q.display()

```

pip install pytest

``` python
import pytest

class TestQueue(unittest.TestCase):

    def setUp(self):
        """Set up a fresh queue before each test."""
        self.queue = Queue()

    def test_enqueue(self):
        """Test enqueue operation."""
        self.queue.enqueue(1)
        self.queue.enqueue(2)
        self.queue.enqueue(3)
        self.assertEqual(self.queue.queue, [1, 2, 3], "Enqueue operation failed")

    def test_dequeue(self):
        """Test dequeue operation."""
        self.queue.enqueue(1)
        self.queue.enqueue(2)
        self.queue.enqueue(3)
        item = self.queue.dequeue()
        self.assertEqual(item, 1, "Dequeue operation failed to return the correct item")
        self.assertEqual(self.queue.queue, [2, 3], "Dequeue operation did not update the queue correctly")

    def test_dequeue_empty(self):
        """Test dequeue operation on an empty queue."""
        item = self.queue.dequeue()
        self.assertIsNone(item, "Dequeue operation on an empty queue did not return None")
    
    def test_size(self):
        """Test the size of the queue."""
        self.queue.enqueue(1)
        self.queue.enqueue(2)
        self.queue.enqueue(3)
        self.assertEqual(self.queue.size(), 3, "Size method returned the incorrect size")
        self.queue.dequeue()
        self.assertEqual(self.queue.size(), 2, "Size method did not update after dequeue operation")

    def test_display(self):
        """Test display method."""
        self.queue.enqueue(1)
        self.queue.enqueue(2)
        self.queue.enqueue(3)
        with self.assertLogs() as captured:
            self.queue.display()
            self.assertIn("[1, 2, 3]", captured.output[0], "Display method did not print the correct queue state")

if __name__ == '__main__':
    unittest.main()

```