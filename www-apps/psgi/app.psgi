my $app = sub {
    my $env = shift;
    my $path = $env->{PATH_INFO} || '/';
    return [ 200, [ 'Content-Type' => 'text/plain' ], [ "hello from psgi path=$path\n" ] ];
};
$app;
