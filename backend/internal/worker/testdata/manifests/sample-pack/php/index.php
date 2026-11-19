<?php
// Deliberately vulnerable sample for the worker-sast fixture tests.

function find_user(mysqli $db): void
{
    $id = $_GET['id'];
    $result = mysqli_query($db, "SELECT * FROM users WHERE id = " . $id);
    echo "Hello " . $_GET['name'];
    system("ping -c 1 " . $_POST['host']);
    include $_GET['page'];
    $count = strlen(42, 'extra');
    undefined_helper($result);
}

class Report
{
    public function total(array $rows): int
    {
        return $this->sumRows($rows) + "items";
    }
}
