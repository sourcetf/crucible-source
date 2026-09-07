my $app = sub {
    my $env = shift;
    my $path = $env->{PATH_INFO} // '/';
    return [
        200,
        [ 'Content-Type' => 'text/plain; charset=utf-8' ],
        [ "hello from psgi index path=$path\n" ],
    ];
};
$app;
