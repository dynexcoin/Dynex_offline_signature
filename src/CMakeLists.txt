add_definitions(-DSTATICLIB -DMINIUPNP_STATICLIB)

file(GLOB_RECURSE Common Common/*)
file(GLOB_RECURSE Serialization Serialization/*)
file(GLOB_RECURSE offline offline/*)
file(GLOB_RECURSE Crypto crypto/*)
file(GLOB_RECURSE DynexCNCore DynexCNCore/*)
file(GLOB_RECURSE Mnemonics Mnemonics/*)

source_group("" FILES $${Common} ${offline} ${Crypto} ${DynexCNCore} ${Serialization} ${Mnemonics})

add_library(Common ${Common})
add_library(Serialization ${Serialization})
add_library(Crypto ${Crypto})
add_library(DynexCNCore ${DynexCNCore})
add_library(Mnemonics ${Mnemonics})

add_executable(offline ${offline})

target_link_libraries(offline DynexCNCore Mnemonics Crypto Serialization Common)

set_property(TARGET offline PROPERTY OUTPUT_NAME "offlinesignature")
