#include <boost/json/src.hpp>
#include "omf_routine.hpp"
#define BOOST_TEST_MODULE mytests
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_CASE(myTestCase)
{
	BOOST_TEST(omf_routine(true));
}