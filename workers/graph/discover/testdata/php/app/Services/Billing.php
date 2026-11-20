<?php
// Example billing service (test fixture for pathos-graph; not run).
namespace App\Services;

class Billing
{
    public function total($id)
    {
        return self::format($id * 3);
    }

    public static function format($v)
    {
        return number_format($v, 2);
    }
}
