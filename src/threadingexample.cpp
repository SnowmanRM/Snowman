// Compile with: g++ test.cpp -lboost_thread -lboost_system -o test

#include <boost/thread/thread.hpp>
#include <iostream>
#include <stdio.h>

using namespace std;
using namespace boost;
using namespace boost::this_thread;

void hello(int i)
{
sleep(posix_time::seconds(i*10%2));
cout <<
"I am a thread, nr "<<i<<" and i waited " << i*10%3 << " seconds"
<< endl;

}

int main(int argc, char* argv[])
{
thread_group threads;
for(int i=1;i<=10;i++) {
thread* t=new thread(&hello, i);
threads.add_thread(t);
}

threads.join_all();
return 0;
}
